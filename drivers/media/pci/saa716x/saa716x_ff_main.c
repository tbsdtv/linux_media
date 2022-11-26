#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/mutex.h>

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/byteorder.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/firmware.h>

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>

#include <linux/i2c.h>

#include <linux/videodev2.h>
#include <linux/dvb/video.h>
#include <linux/dvb/audio.h>
#include <linux/dvb/osd.h>

#include "saa716x_mod.h"

#include "saa716x_dma_reg.h"
#include "saa716x_fgpi_reg.h"
#include "saa716x_greg_reg.h"
#include "saa716x_phi_reg.h"
#include "saa716x_spi_reg.h"
#include "saa716x_msi_reg.h"

#include "saa716x_msi.h"
#include "saa716x_adap.h"
#include "saa716x_gpio.h"
#include "saa716x_phi.h"
#include "saa716x_rom.h"
#include "saa716x_spi.h"
#include "saa716x_priv.h"

#include "saa716x_ff.h"
#include "saa716x_ff_cmd.h"

#include "stv6110x.h"
#include "stv090x.h"
#include "isl6423.h"

unsigned int verbose;
module_param(verbose, int, 0644);
MODULE_PARM_DESC(verbose, "verbose startup messages, default is 1 (yes)");

unsigned int int_type;
module_param(int_type, int, 0644);
MODULE_PARM_DESC(int_type, "force Interrupt Handler type: 0=INT-A, 1=MSI, 2=MSI-X. default INT-A mode");

unsigned int int_count_enable;
module_param(int_count_enable, int, 0644);
MODULE_PARM_DESC(int_count_enable, "enable counting of interrupts");

unsigned int video_capture;
module_param(video_capture, int, 0644);
MODULE_PARM_DESC(video_capture, "capture digital video coming from STi7109: 0=off, 1=one-shot. default off");

#define DRIVER_NAME	"SAA716x FF"

static int saa716x_ff_fpga_init(struct saa716x_dev *saa716x)
{
	struct sti7109_dev *sti7109 = saa716x->priv;
	int fpgaInit;
	int fpgaDone;
	int rounds;
	int ret;
	const struct firmware *fw;

	/* request the FPGA firmware, this will block until someone uploads it */
	ret = request_firmware(&fw, "dvb-ttpremium-fpga-01.fw", &saa716x->pdev->dev);
	if (ret) {
		if (ret == -ENOENT) {
			printk(KERN_ERR "dvb-ttpremium: could not load FPGA firmware,"
			       " file not found: dvb-ttpremium-fpga-01.fw\n");
			printk(KERN_ERR "dvb-ttpremium: usually this should be in "
			       "/usr/lib/hotplug/firmware or /lib/firmware\n");
		} else
			printk(KERN_ERR "dvb-ttpremium: cannot request firmware"
			       " (error %i)\n", ret);
		return -EINVAL;
	}

	/* set FPGA PROGRAMN high */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_FPGA_PROGRAMN, 1);
	msleep(10);

	/* set FPGA PROGRAMN low to set it into configuration mode */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_FPGA_PROGRAMN, 0);
	msleep(10);

	/* set FPGA PROGRAMN high to start configuration process */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_FPGA_PROGRAMN, 1);

	rounds = 0;
	fpgaInit = saa716x_gpio_read(saa716x, TT_PREMIUM_GPIO_FPGA_INITN);
	while (fpgaInit == 0 && rounds < 5000) {
		//msleep(1);
		fpgaInit = saa716x_gpio_read(saa716x, TT_PREMIUM_GPIO_FPGA_INITN);
		rounds++;
	}
	dprintk(SAA716x_INFO, 1, "SAA716x FF FPGA INITN=%d, rounds=%d",
		fpgaInit, rounds);

	SAA716x_EPWR(SPI, SPI_CLOCK_COUNTER, 0x08);
	SAA716x_EPWR(SPI, SPI_CONTROL_REG, SPI_MODE_SELECT);

	msleep(10);

	fpgaDone = saa716x_gpio_read(saa716x, TT_PREMIUM_GPIO_FPGA_DONE);
	dprintk(SAA716x_INFO, 1, "SAA716x FF FPGA DONE=%d", fpgaDone);
	dprintk(SAA716x_INFO, 1, "SAA716x FF FPGA write bitstream");
	saa716x_spi_write(saa716x, fw->data, fw->size);
	dprintk(SAA716x_INFO, 1, "SAA716x FF FPGA write bitstream done");
	fpgaDone = saa716x_gpio_read(saa716x, TT_PREMIUM_GPIO_FPGA_DONE);
	dprintk(SAA716x_INFO, 1, "SAA716x FF FPGA DONE=%d", fpgaDone);

	msleep(10);

	release_firmware(fw);

	if (!fpgaDone) {
		printk(KERN_ERR "SAA716x FF FPGA is not responding, did you "
				"connect the power supply?\n");
		return -EINVAL;
	}

	sti7109->fpga_version = SAA716x_EPRD(PHI_1, FPGA_ADDR_VERSION);
	printk(KERN_INFO "SAA716x FF FPGA version %X.%02X\n",
		sti7109->fpga_version >> 8, sti7109->fpga_version & 0xFF);

	return 0;
}

static int saa716x_ff_st7109_init(struct saa716x_dev *saa716x)
{
	int i;
	int length;
	u32 requestedBlock;
	u32 writtenBlock;
	u32 numBlocks;
	u32 blockSize;
	u32 lastBlockSize;
	u64 startTime;
	u64 currentTime;
	u64 waitTime;
	int ret;
	const struct firmware *fw;
	u32 loaderVersion;

	/* request the st7109 loader, this will block until someone uploads it */
	ret = request_firmware(&fw, "dvb-ttpremium-loader-01.fw", &saa716x->pdev->dev);
	if (ret) {
		if (ret == -ENOENT) {
			printk(KERN_ERR "dvb-ttpremium: could not load ST7109 loader,"
			       " file not found: dvb-ttpremium-loader-01.fw\n");
			printk(KERN_ERR "dvb-ttpremium: usually this should be in "
			       "/usr/lib/hotplug/firmware or /lib/firmware\n");
		} else
			printk(KERN_ERR "dvb-ttpremium: cannot request firmware"
			       " (error %i)\n", ret);
		return -EINVAL;
	}
	loaderVersion = (fw->data[0x1385] << 8) | fw->data[0x1384];
	printk(KERN_INFO "SAA716x FF loader version %X.%02X\n",
		loaderVersion >> 8, loaderVersion & 0xFF);

	saa716x_phi_write(saa716x, 0, fw->data, fw->size);
	msleep(10);

	release_firmware(fw);

	/* take ST out of reset */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_RESET_BACKEND, 1);

	startTime = jiffies;
	waitTime = 0;
	do {
		requestedBlock = SAA716x_EPRD(PHI_1, 0x3ffc);
		if (requestedBlock == 1)
			break;

		currentTime = jiffies;
		waitTime = currentTime - startTime;
	} while (waitTime < (1 * HZ));

	if (waitTime >= 1 * HZ) {
		dprintk(SAA716x_ERROR, 1, "STi7109 seems to be DEAD!");
		return -1;
	}
	dprintk(SAA716x_INFO, 1, "STi7109 ready after %llu ticks", waitTime);

	/* request the st7109 firmware, this will block until someone uploads it */
	ret = request_firmware(&fw, "dvb-ttpremium-st7109-01.fw", &saa716x->pdev->dev);
	if (ret) {
		if (ret == -ENOENT) {
			printk(KERN_ERR "dvb-ttpremium: could not load ST7109 firmware,"
			       " file not found: dvb-ttpremium-st7109-01.fw\n");
			printk(KERN_ERR "dvb-ttpremium: usually this should be in "
			       "/usr/lib/hotplug/firmware or /lib/firmware\n");
		} else
			printk(KERN_ERR "dvb-ttpremium: cannot request firmware"
			       " (error %i)\n", ret);
		return -EINVAL;
	}

	dprintk(SAA716x_INFO, 1, "SAA716x FF download ST7109 firmware");
	writtenBlock = 0;
	blockSize = 0x3c00;
	length = fw->size;
	numBlocks = length / blockSize;
	lastBlockSize = length % blockSize;
	for (i = 0; i < length; i += blockSize) {
		writtenBlock++;
		/* write one block (last may differ from blockSize) */
		if (lastBlockSize && writtenBlock == (numBlocks + 1))
			saa716x_phi_write(saa716x, 0, &fw->data[i], lastBlockSize);
		else
			saa716x_phi_write(saa716x, 0, &fw->data[i], blockSize);

		SAA716x_EPWR(PHI_1, 0x3ff8, writtenBlock);
		startTime = jiffies;
		waitTime = 0;
		do {
			requestedBlock = SAA716x_EPRD(PHI_1, 0x3ffc);
			if (requestedBlock == (writtenBlock + 1))
				break;

			currentTime = jiffies;
			waitTime = currentTime - startTime;
		} while (waitTime < (1 * HZ));

		if (waitTime >= 1 * HZ) {
			dprintk(SAA716x_ERROR, 1, "STi7109 seems to be DEAD!");
			release_firmware(fw);
			return -1;
		}
	}

	/* disable frontend support through ST firmware */
	SAA716x_EPWR(PHI_1, 0x3ff4, 1);

	/* indicate end of transfer */
	writtenBlock++;
	writtenBlock |= 0x80000000;
	SAA716x_EPWR(PHI_1, 0x3ff8, writtenBlock);

	dprintk(SAA716x_INFO, 1, "SAA716x FF download ST7109 firmware done");

	release_firmware(fw);

	return 0;
}

static int saa716x_usercopy(struct dvb_device *dvbdev,
			    unsigned int cmd, unsigned long arg,
			    int (*func)(struct dvb_device *dvbdev,
			    unsigned int cmd, void *arg))
{
	char    sbuf[128];
	void    *mbuf = NULL;
	void    *parg = NULL;
	int     err  = -EINVAL;

	/*  Copy arguments into temp kernel buffer  */
	switch (_IOC_DIR(cmd)) {
	case _IOC_NONE:
		/*
		 * For this command, the pointer is actually an integer
		 * argument.
		 */
		parg = (void *) arg;
		break;
	case _IOC_READ: /* some v4l ioctls are marked wrong ... */
	case _IOC_WRITE:
	case (_IOC_WRITE | _IOC_READ):
		if (_IOC_SIZE(cmd) <= sizeof(sbuf)) {
			parg = sbuf;
		} else {
			/* too big to allocate from stack */
			mbuf = kmalloc(_IOC_SIZE(cmd),GFP_KERNEL);
			if (NULL == mbuf)
				return -ENOMEM;
			parg = mbuf;
		}

		err = -EFAULT;
		if (copy_from_user(parg, (void __user *)arg, _IOC_SIZE(cmd)))
			goto out;
		break;
	}

	/* call driver */
	if ((err = func(dvbdev, cmd, parg)) == -ENOIOCTLCMD)
		err = -EINVAL;

	if (err < 0)
		goto out;

	/*  Copy results into user buffer  */
	switch (_IOC_DIR(cmd))
	{
	case _IOC_READ:
	case (_IOC_WRITE | _IOC_READ):
		if (copy_to_user((void __user *)arg, parg, _IOC_SIZE(cmd)))
			err = -EFAULT;
		break;
	}

out:
	kfree(mbuf);
	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(EXPERIMENTAL_TREE)
static int dvb_osd_ioctl(struct inode *inode, struct file *file,
#else
static long dvb_osd_ioctl(struct file *file,
#endif
			 unsigned int cmd, unsigned long arg)
{
	struct dvb_device *dvbdev = file->private_data;
	struct sti7109_dev *sti7109 = dvbdev->priv;
	int err = -EINVAL;

	if (!dvbdev)
		return -ENODEV;

	if (cmd == OSD_RAW_CMD) {
		osd_raw_cmd_t raw_cmd;
		u8 hdr[4];

		err = -EFAULT;
		if (copy_from_user(&raw_cmd, (void __user *)arg,
				   _IOC_SIZE(cmd)))
			goto out;

		if (copy_from_user(hdr, (void __user *)raw_cmd.cmd_data, 4))
			goto out;

		if (hdr[3] == 4)
			err = sti7109_raw_osd_cmd(sti7109, &raw_cmd);
		else
			err = sti7109_raw_cmd(sti7109, &raw_cmd);

		if (err)
			goto out;

		if (copy_to_user((void __user *)arg, &raw_cmd, _IOC_SIZE(cmd)))
			err = -EFAULT;
	}
	else if (cmd == OSD_RAW_DATA) {
		osd_raw_data_t raw_data;

		err = -EFAULT;
		if (copy_from_user(&raw_data, (void __user *)arg,
				   _IOC_SIZE(cmd)))
			goto out;

		err = sti7109_raw_data(sti7109, &raw_data);
		if (err)
			goto out;

		if (copy_to_user((void __user *)arg, &raw_data, _IOC_SIZE(cmd)))
			err = -EFAULT;
	}

out:
	return err;
}

static struct file_operations dvb_osd_fops = {
	.owner		= THIS_MODULE,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(EXPERIMENTAL_TREE)
	.ioctl		= dvb_osd_ioctl,
#else
	.unlocked_ioctl	= dvb_osd_ioctl,
#endif
	.open		= dvb_generic_open,
	.release	= dvb_generic_release,
};

static struct dvb_device dvbdev_osd = {
	.priv		= NULL,
	.users		= 2,
	.writers	= 2,
	.fops		= &dvb_osd_fops,
	.kernel_ioctl	= NULL,
};

static int saa716x_ff_osd_exit(struct saa716x_dev *saa716x)
{
	struct sti7109_dev *sti7109 = saa716x->priv;

	dvb_unregister_device(sti7109->osd_dev);
	return 0;
}

static int saa716x_ff_osd_init(struct saa716x_dev *saa716x)
{
	struct saa716x_adapter *saa716x_adap	= saa716x->saa716x_adap;
	struct sti7109_dev *sti7109		= saa716x->priv;

	dvb_register_device(&saa716x_adap->dvb_adapter,
			    &sti7109->osd_dev,
			    &dvbdev_osd,
			    sti7109,
			    DVB_DEVICE_OSD, 0);

	return 0;
}

static int do_dvb_audio_ioctl(struct dvb_device *dvbdev,
			      unsigned int cmd, void *parg)
{
	struct sti7109_dev *sti7109	= dvbdev->priv;
	//struct saa716x_dev *saa716x	= sti7109->dev;
	int ret = 0;

	switch (cmd) {
	case AUDIO_GET_PTS:
	{
		*(u64 *)parg = sti7109->audio_pts;
		break;
	}
	default:
		ret = -ENOIOCTLCMD;
		break;
	}
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(EXPERIMENTAL_TREE)
static int dvb_audio_ioctl(struct inode *inode, struct file *file,
#else
static long dvb_audio_ioctl(struct file *file,
#endif
			   unsigned int cmd, unsigned long arg)
{
	struct dvb_device *dvbdev = file->private_data;

	if (!dvbdev)
		return -ENODEV;

	return saa716x_usercopy (dvbdev, cmd, arg, do_dvb_audio_ioctl);
}

static struct file_operations dvb_audio_fops = {
	.owner		= THIS_MODULE,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(EXPERIMENTAL_TREE)
	.ioctl		= dvb_audio_ioctl,
#else
	.unlocked_ioctl	= dvb_audio_ioctl,
#endif
	.open		= dvb_generic_open,
	.release	= dvb_generic_release,
};

static struct dvb_device dvbdev_audio = {
	.priv		= NULL,
	.users		= 1,
	.writers	= 1,
	.fops		= &dvb_audio_fops,
	.kernel_ioctl	= NULL,
};

static int saa716x_ff_audio_exit(struct saa716x_dev *saa716x)
{
	struct sti7109_dev *sti7109 = saa716x->priv;

	dvb_unregister_device(sti7109->audio_dev);
	return 0;
}

static int saa716x_ff_audio_init(struct saa716x_dev *saa716x)
{
	struct saa716x_adapter *saa716x_adap	= saa716x->saa716x_adap;
	struct sti7109_dev *sti7109		= saa716x->priv;

	dvb_register_device(&saa716x_adap->dvb_adapter,
			    &sti7109->audio_dev,
			    &dvbdev_audio,
			    sti7109,
			    DVB_DEVICE_AUDIO, 0);

	return 0;
}

static ssize_t ringbuffer_write_user(struct dvb_ringbuffer *rbuf, const u8 __user *buf, size_t len)
{
	size_t todo = len;
	size_t split;

	split = (rbuf->pwrite + len > rbuf->size) ? rbuf->size - rbuf->pwrite : 0;

	if (split > 0) {
        	if (copy_from_user(rbuf->data+rbuf->pwrite, buf, split)) {
			return -EFAULT;
		}
		buf += split;
		todo -= split;
		rbuf->pwrite = 0;
	}
	if (copy_from_user(rbuf->data+rbuf->pwrite, buf, todo)) {
		return -EFAULT;
	}
	rbuf->pwrite = (rbuf->pwrite + todo) % rbuf->size;

	return len;
}

static void ringbuffer_read_io32(struct dvb_ringbuffer *rbuf, u32 __iomem *buf, size_t len)
{
	size_t todo = len;
	size_t split;

	split = (rbuf->pread + len > rbuf->size) ? rbuf->size - rbuf->pread : 0;
	if (split > 0) {
		iowrite32_rep(buf, rbuf->data+rbuf->pread, split/4);
		buf += split;
		todo -= split;
		rbuf->pread = 0;
	}
	iowrite32_rep(buf, rbuf->data+rbuf->pread, todo/4);

	rbuf->pread = (rbuf->pread + todo) % rbuf->size;
}

static void fifo_worker(struct work_struct *work)
{
	struct sti7109_dev *sti7109 = container_of(work, struct sti7109_dev, fifo_work);
	struct saa716x_dev *saa716x = sti7109->dev;
	u32 fifoCtrl;
	u32 fifoStat;
	u16 fifoSize;
	u16 fifoUsage;
	u16 fifoFree;
	int len;

	if (sti7109->tsout_stat == TSOUT_STAT_RESET)
		return;

	fifoStat = SAA716x_EPRD(PHI_1, FPGA_ADDR_FIFO_STAT);
	fifoSize = (u16) (fifoStat >> 16);
	fifoUsage = (u16) fifoStat;
	fifoFree = fifoSize - fifoUsage - 1;
	len = dvb_ringbuffer_avail(&sti7109->tsout);
	if (len > fifoFree)
		len = fifoFree;
	if (len < TS_SIZE)
		return;

	while (len >= TS_SIZE)
	{
		ringbuffer_read_io32(&sti7109->tsout, saa716x->mmio + PHI_0 + PHI_0_0_RW_0, (size_t) TS_SIZE);
		len -= TS_SIZE;
	}
	wake_up(&sti7109->tsout.queue);

	spin_lock(&sti7109->tsout.lock);
	if (sti7109->tsout_stat != TSOUT_STAT_RESET) {
		sti7109->tsout_stat = TSOUT_STAT_RUN;

		fifoCtrl = SAA716x_EPRD(PHI_1, FPGA_ADDR_FIFO_CTRL);
		fifoCtrl |= 0x4;
		SAA716x_EPWR(PHI_1, FPGA_ADDR_FIFO_CTRL, fifoCtrl);
	}
	spin_unlock(&sti7109->tsout.lock);
}

static void video_vip_worker(unsigned long data)
{
	struct saa716x_vip_stream_port *vip_entry = (struct saa716x_vip_stream_port *)data;
	struct saa716x_dev *saa716x = vip_entry->saa716x;
	u32 vip_index;
	u32 write_index;

	vip_index = vip_entry->dma_channel[0];
	if (vip_index != 0) {
		printk(KERN_ERR "%s: unexpected channel %u\n",
		       __func__, vip_entry->dma_channel[0]);
		return;
	}

	write_index = saa716x_vip_get_write_index(saa716x, vip_index);
	if (write_index < 0)
		return;

	dprintk(SAA716x_DEBUG, 1, "dma buffer = %d", write_index);

	if (write_index == vip_entry->read_index) {
		printk(KERN_DEBUG "%s: called but nothing to do\n", __func__);
		return;
	}

	do {
		dma_sync_sg_for_cpu(&saa716x->pdev->dev,
			vip_entry->dma_buf[0][vip_entry->read_index].sg_list,
			vip_entry->dma_buf[0][vip_entry->read_index].list_len,
			DMA_FROM_DEVICE);
		if (vip_entry->dual_channel) {
			dma_sync_sg_for_cpu(&saa716x->pdev->dev,
				vip_entry->dma_buf[1][vip_entry->read_index].sg_list,
				vip_entry->dma_buf[1][vip_entry->read_index].list_len,
				DMA_FROM_DEVICE);
		}

		vip_entry->read_index = (vip_entry->read_index + 1) & 7;
	} while (write_index != vip_entry->read_index);
}

static int video_vip_get_stream_params(struct vip_stream_params * params,
				       u32 mode)
{
	switch (mode)
	{
		case 4:  /* 1280x720p60 */
		case 19: /* 1280x720p50 */
			params->bits		= 16;
			params->samples		= 1280;
			params->lines		= 720;
			params->pitch		= 1280 * 2;
			params->offset_x	= 32;
			params->offset_y	= 30;
			params->stream_flags	= VIP_HD;
			break;

		case 5:  /* 1920x1080i60 */
		case 20: /* 1920x1080i50 */
			params->bits		= 16;
			params->samples		= 1920;
			params->lines		= 1080;
			params->pitch		= 1920 * 2;
			params->offset_x	= 0;
			params->offset_y	= 20;
			params->stream_flags	= VIP_ODD_FIELD
						| VIP_EVEN_FIELD
						| VIP_INTERLACED
						| VIP_HD
						| VIP_NO_SCALER;
			break;

		case 32: /* 1920x1080p24 */
		case 33: /* 1920x1080p25 */
		case 34: /* 1920x1080p30 */
			params->bits		= 16;
			params->samples		= 1920;
			params->lines		= 1080;
			params->pitch		= 1920 * 2;
			params->offset_x	= 0;
			params->offset_y	= 0;
			params->stream_flags	= VIP_HD;
			break;

		default:
			return -1;
	}
	return 0;
}

static ssize_t video_vip_read(struct sti7109_dev *sti7109,
			      struct vip_stream_params * stream_params,
			      char __user *buf, size_t count)
{
	struct saa716x_dev *saa716x = sti7109->dev;
	struct v4l2_pix_format pix_format;
	int one_shot = 0;
	size_t num_bytes;
	size_t copy_bytes;
	u32 read_index;
	u8 *data;
	int err = 0;

	if (sti7109->video_capture == VIDEO_CAPTURE_ONE_SHOT)
		one_shot = 1;

	/* put a v4l2_pix_format header at the beginning of the returned data */
	memset(&pix_format, 0, sizeof(pix_format));
	pix_format.width	= stream_params->samples;
	pix_format.height	= stream_params->lines;
	pix_format.pixelformat	= V4L2_PIX_FMT_UYVY;
	pix_format.bytesperline	= stream_params->pitch;
	pix_format.sizeimage	= stream_params->lines * stream_params->pitch;

	if (count > (sizeof(pix_format) + pix_format.sizeimage))
		count = sizeof(pix_format) + pix_format.sizeimage;

	if (count < sizeof(pix_format)) {
		err = -EFAULT;
		goto out;
	}

	saa716x_vip_start(saa716x, 0, one_shot, stream_params);
	/* Sleep long enough to be sure to capture at least one frame.
	   TODO: Change this in a way that it just waits the required time. */
	msleep(100);
	saa716x_vip_stop(saa716x, 0);

	read_index = saa716x->vip[0].read_index;
	if ((stream_params->stream_flags & VIP_INTERLACED) &&
	    (stream_params->stream_flags & VIP_ODD_FIELD) &&
	    (stream_params->stream_flags & VIP_EVEN_FIELD)) {
		read_index = read_index & ~1;
		read_index = (read_index + 7) & 7;
		read_index = read_index / 2;
	} else {
		read_index = (read_index + 7) & 7;
	}

	if (copy_to_user((void __user *)buf, &pix_format, sizeof(pix_format))) {
		err = -EFAULT;
		goto out;
	}
	num_bytes = sizeof(pix_format);

	copy_bytes = count - num_bytes;
	if (copy_bytes > (SAA716x_PAGE_SIZE / 8 * SAA716x_PAGE_SIZE))
		copy_bytes = SAA716x_PAGE_SIZE / 8 * SAA716x_PAGE_SIZE;
	data = (u8 *)saa716x->vip[0].dma_buf[0][read_index].mem_virt;
	if (copy_to_user((void __user *)(buf + num_bytes), data, copy_bytes)) {
		err = -EFAULT;
		goto out;
	}
	num_bytes += copy_bytes;
	if (saa716x->vip[0].dual_channel &&
	    count - num_bytes > 0) {
		copy_bytes = count - num_bytes;
		if (copy_bytes > (SAA716x_PAGE_SIZE / 8 * SAA716x_PAGE_SIZE))
			copy_bytes = SAA716x_PAGE_SIZE / 8 * SAA716x_PAGE_SIZE;
		data = (u8 *)saa716x->vip[0].dma_buf[1][read_index].mem_virt;
		if (copy_to_user((void __user *)(buf + num_bytes), data,
				 copy_bytes)) {
			err = -EFAULT;
			goto out;
		}
		num_bytes += copy_bytes;
	}

	return num_bytes;

out:
	return err;
}

static ssize_t dvb_video_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct dvb_device *dvbdev	= file->private_data;
	struct sti7109_dev *sti7109	= dvbdev->priv;
	struct vip_stream_params stream_params;
	ssize_t ret = -ENODATA;

	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		return -EPERM;

	mutex_lock(&sti7109->video_lock);

	if (sti7109->video_capture != VIDEO_CAPTURE_OFF) {
		if (video_vip_get_stream_params(&stream_params,
						sti7109->video_format) == 0) {
			ret = video_vip_read(sti7109, &stream_params,
					     buf, count);
		}
	}

	mutex_unlock(&sti7109->video_lock);
	return ret;
}

#define FREE_COND_TS (dvb_ringbuffer_free(&sti7109->tsout) >= TS_SIZE)

static ssize_t dvb_video_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct dvb_device *dvbdev	= file->private_data;
	struct sti7109_dev *sti7109	= dvbdev->priv;
	struct saa716x_dev *saa716x	= sti7109->dev;
	unsigned long todo = count;

	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		return -EPERM;
/*
	if (av7110->videostate.stream_source != VIDEO_SOURCE_MEMORY)
		return -EPERM;
*/
	if (sti7109->tsout_stat == TSOUT_STAT_RESET)
		return count;

	if ((file->f_flags & O_NONBLOCK) && !FREE_COND_TS)
		return -EWOULDBLOCK;

	while (todo >= TS_SIZE) {
		if (!FREE_COND_TS) {
			if (file->f_flags & O_NONBLOCK)
				break;
			if (wait_event_interruptible(sti7109->tsout.queue, FREE_COND_TS))
				break;
		}
		ringbuffer_write_user(&sti7109->tsout, buf, TS_SIZE);
		todo -= TS_SIZE;
		buf += TS_SIZE;
	}

	if ((sti7109->tsout_stat == TSOUT_STAT_RUN) ||
	    (dvb_ringbuffer_avail(&sti7109->tsout) > TSOUT_LEN/3)) {
		u32 fifoCtrl = SAA716x_EPRD(PHI_1, FPGA_ADDR_FIFO_CTRL);
		fifoCtrl |= 0x4;
		SAA716x_EPWR(PHI_1, FPGA_ADDR_FIFO_CTRL, fifoCtrl);
	}

	return count - todo;
}

static unsigned int dvb_video_poll(struct file *file, poll_table *wait)
{
	struct dvb_device *dvbdev	= file->private_data;
	struct sti7109_dev *sti7109	= dvbdev->priv;
	unsigned int mask = 0;

	if ((file->f_flags & O_ACCMODE) != O_RDONLY) {
		poll_wait(file, &sti7109->tsout.queue, wait);

		if (FREE_COND_TS)
			mask |= (POLLOUT | POLLWRNORM);
	}

	return mask;
}

static int do_dvb_video_ioctl(struct dvb_device *dvbdev,
			      unsigned int cmd, void *parg)
{
	struct sti7109_dev *sti7109	= dvbdev->priv;
	struct saa716x_dev *saa716x	= sti7109->dev;
	int ret = 0;

	switch (cmd) {
	case VIDEO_SELECT_SOURCE:
	{
		video_stream_source_t stream_source;

		stream_source = (video_stream_source_t) parg;
		if (stream_source == VIDEO_SOURCE_DEMUX) {
			/* stop and reset FIFO 1 */
			SAA716x_EPWR(PHI_1, FPGA_ADDR_FIFO_CTRL, 1);
			sti7109->tsout_stat = TSOUT_STAT_RESET;
			break;
		}
		/* fall through */
	}
	case VIDEO_CLEAR_BUFFER:
	{
		/* reset FIFO 1 */
		spin_lock(&sti7109->tsout.lock);
		SAA716x_EPWR(PHI_1, FPGA_ADDR_FIFO_CTRL, 1);
		sti7109->tsout_stat = TSOUT_STAT_RESET;
		spin_unlock(&sti7109->tsout.lock);
		msleep(50);
		cancel_work_sync(&sti7109->fifo_work);
		/* start FIFO 1 */
		SAA716x_EPWR(PHI_1, FPGA_ADDR_FIFO_CTRL, 2);
		dvb_ringbuffer_flush(&sti7109->tsout);
        	sti7109->tsout_stat = TSOUT_STAT_FILL;
		wake_up(&sti7109->tsout.queue);
		break;
	}
	case VIDEO_GET_PTS:
	{
		*(u64 *)parg = sti7109->video_pts;
		break;
	}
	case VIDEO_GET_SIZE:
	{
		ret = sti7109_cmd_get_video_format(sti7109, (video_size_t *) parg);
		break;
	}
	default:
		ret = -ENOIOCTLCMD;
		break;
	}
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(EXPERIMENTAL_TREE)
static int dvb_video_ioctl(struct inode *inode, struct file *file,
#else
static long dvb_video_ioctl(struct file *file,
#endif
			   unsigned int cmd, unsigned long arg)
{
	struct dvb_device *dvbdev = file->private_data;

	if (!dvbdev)
		return -ENODEV;

	return saa716x_usercopy (dvbdev, cmd, arg, do_dvb_video_ioctl);
}

static struct file_operations dvb_video_fops = {
	.owner		= THIS_MODULE,
	.read		= dvb_video_read,
	.write		= dvb_video_write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && !defined(EXPERIMENTAL_TREE)
	.ioctl		= dvb_video_ioctl,
#else
	.unlocked_ioctl	= dvb_video_ioctl,
#endif
	.open		= dvb_generic_open,
	.release	= dvb_generic_release,
	.poll		= dvb_video_poll,
};

static struct dvb_device dvbdev_video = {
	.priv		= NULL,
	.users		= 5,
	.readers	= 5,
	.writers	= 1,
	.fops		= &dvb_video_fops,
	.kernel_ioctl	= NULL,
};

static int saa716x_ff_video_exit(struct saa716x_dev *saa716x)
{
	struct sti7109_dev *sti7109 = saa716x->priv;

	if (sti7109->video_capture != VIDEO_CAPTURE_OFF)
		saa716x_vip_exit(saa716x, 0);

	cancel_work_sync(&sti7109->fifo_work);
	destroy_workqueue(sti7109->fifo_workq);
	dvb_unregister_device(sti7109->video_dev);
	return 0;
}

static int saa716x_ff_video_init(struct saa716x_dev *saa716x)
{
	struct saa716x_adapter *saa716x_adap	= saa716x->saa716x_adap;
	struct sti7109_dev *sti7109		= saa716x->priv;

	dvb_ringbuffer_init(&sti7109->tsout, sti7109->iobuf, TSOUT_LEN);

	dvb_register_device(&saa716x_adap->dvb_adapter,
			    &sti7109->video_dev,
			    &dvbdev_video,
			    sti7109,
			    DVB_DEVICE_VIDEO, 0);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	sti7109->fifo_workq = create_singlethread_workqueue("saa716x_fifo_wq");
#else
	sti7109->fifo_workq = alloc_workqueue("saa716x_fifo_wq%d", WQ_UNBOUND, 1, SAA716x_DEV);
#endif
	INIT_WORK(&sti7109->fifo_work, fifo_worker);

	if (sti7109->video_capture != VIDEO_CAPTURE_OFF)
		saa716x_vip_init(saa716x, 0, video_vip_worker);

	return 0;
}

static int saa716x_ff_pci_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
	struct saa716x_dev *saa716x;
	struct sti7109_dev *sti7109;
	int err = 0;
	u32 value;
	unsigned long timeout;
	u32 fw_version;

	saa716x = kzalloc(sizeof (struct saa716x_dev), GFP_KERNEL);
	if (saa716x == NULL) {
		printk(KERN_ERR "saa716x_budget_pci_probe ERROR: out of memory\n");
		err = -ENOMEM;
		goto fail0;
	}

	saa716x->verbose	= verbose;
	saa716x->int_type	= int_type;
	saa716x->pdev		= pdev;
	saa716x->module		= THIS_MODULE;
	saa716x->config		= (struct saa716x_config *) pci_id->driver_data;

	err = saa716x_pci_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x PCI Initialization failed");
		goto fail1;
	}

	err = saa716x_cgu_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x CGU Init failed");
		goto fail1;
	}

	err = saa716x_core_boot(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x Core Boot failed");
		goto fail2;
	}
	dprintk(SAA716x_DEBUG, 1, "SAA716x Core Boot Success");

	err = saa716x_msi_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x MSI Init failed");
		goto fail2;
	}

	err = saa716x_jetpack_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x Jetpack core initialization failed");
		goto fail2;
	}

	err = saa716x_i2c_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x I2C Initialization failed");
		goto fail2;
	}

	err = saa716x_phi_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x PHI Initialization failed");
		goto fail3;
	}

	saa716x_gpio_init(saa716x);

	/* prepare the sti7109 device struct */
	sti7109 = kzalloc(sizeof(struct sti7109_dev), GFP_KERNEL);
	if (!sti7109) {
		dprintk(SAA716x_ERROR, 1, "SAA716x: out of memory");
		goto fail3;
	}

	sti7109->dev = saa716x;

	sti7109->iobuf = vmalloc(TSOUT_LEN + MAX_DATA_LEN);
	if (!sti7109->iobuf)
		goto fail4;

	sti7109_cmd_init(sti7109);

	sti7109->video_capture = video_capture;
	mutex_init(&sti7109->video_lock);

	sti7109->int_count_enable = int_count_enable;
	sti7109->total_int_count = 0;
	memset(sti7109->vi_int_count, 0, sizeof(sti7109->vi_int_count));
	memset(sti7109->fgpi_int_count, 0, sizeof(sti7109->fgpi_int_count));
	memset(sti7109->i2c_int_count, 0, sizeof(sti7109->i2c_int_count));
	sti7109->ext_int_total_count = 0;
	memset(sti7109->ext_int_source_count, 0, sizeof(sti7109->ext_int_source_count));
	sti7109->last_int_ticks = jiffies;

	saa716x->priv = sti7109;

	saa716x_gpio_set_output(saa716x, TT_PREMIUM_GPIO_POWER_ENABLE);
	saa716x_gpio_set_output(saa716x, TT_PREMIUM_GPIO_RESET_BACKEND);
	saa716x_gpio_set_output(saa716x, TT_PREMIUM_GPIO_FPGA_CS0);
	saa716x_gpio_set_mode(saa716x, TT_PREMIUM_GPIO_FPGA_CS0, 1);
	saa716x_gpio_set_output(saa716x, TT_PREMIUM_GPIO_FPGA_CS1);
	saa716x_gpio_set_mode(saa716x, TT_PREMIUM_GPIO_FPGA_CS1, 1);
	saa716x_gpio_set_output(saa716x, TT_PREMIUM_GPIO_FPGA_PROGRAMN);
	saa716x_gpio_set_input(saa716x, TT_PREMIUM_GPIO_FPGA_DONE);
	saa716x_gpio_set_input(saa716x, TT_PREMIUM_GPIO_FPGA_INITN);

	/* hold ST in reset */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_RESET_BACKEND, 0);

	/* enable board power */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_POWER_ENABLE, 1);
	msleep(100);

	err = saa716x_ff_fpga_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x FF FPGA Initialization failed");
		goto fail5;
	}

	/* configure TS muxer */
	if (sti7109->fpga_version < 0x110) {
		/* select FIFO 1 for TS mux 3 */
		SAA716x_EPWR(PHI_1, FPGA_ADDR_TSR_MUX3, 4);
	} else {
		/* select FIFO 1 for TS mux 3 */
		SAA716x_EPWR(PHI_1, FPGA_ADDR_TSR_MUX3, 1);
	}

	/* enable interrupts from ST7109 -> PC */
	SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICTRL, 0x3);

	value = SAA716x_EPRD(MSI, MSI_CONFIG33);
	value &= 0xFCFFFFFF;
	value |= MSI_INT_POL_EDGE_FALL;
	SAA716x_EPWR(MSI, MSI_CONFIG33, value);
	SAA716x_EPWR(MSI, MSI_INT_ENA_SET_H, MSI_INT_EXTINT_0);

	/* enable tuner reset */
	SAA716x_EPWR(PHI_1, FPGA_ADDR_PIO_CTRL, 0);
	msleep(50);
	/* disable tuner reset */
	SAA716x_EPWR(PHI_1, FPGA_ADDR_PIO_CTRL, 1);

	err = saa716x_ff_st7109_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x FF STi7109 initialization failed");
		goto fail5;
	}

	err = saa716x_dump_eeprom(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x EEPROM dump failed");
	}

	err = saa716x_eeprom_data(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x EEPROM dump failed");
	}

	/* enable FGPI2 and FGPI3 for TS inputs */
	SAA716x_EPWR(GREG, GREG_VI_CTRL, 0x0689F04);
	SAA716x_EPWR(GREG, GREG_FGPI_CTRL, 0x280);
	SAA716x_EPWR(GREG, GREG_VIDEO_IN_CTRL, 0xC0);

	err = saa716x_dvb_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x DVB initialization failed");
		goto fail6;
	}

	/* wait a maximum of 10 seconds for the STi7109 to boot */
	timeout = 10 * HZ;
	timeout = wait_event_interruptible_timeout(sti7109->boot_finish_wq,
						   sti7109->boot_finished == 1,
						   timeout);

	if (timeout == -ERESTARTSYS || sti7109->boot_finished == 0) {
		if (timeout == -ERESTARTSYS) {
			/* a signal arrived */
			goto fail6;
		}
		dprintk(SAA716x_ERROR, 1, "timed out waiting for boot finish");
		err = -1;
		goto fail6;
	}
	dprintk(SAA716x_INFO, 1, "STi7109 finished booting");

	err = saa716x_ff_video_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x FF VIDEO initialization failed");
		goto fail7;
	}

	err = saa716x_ff_audio_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x FF AUDIO initialization failed");
		goto fail8;
	}

	err = saa716x_ff_osd_init(saa716x);
	if (err) {
		dprintk(SAA716x_ERROR, 1, "SAA716x FF OSD initialization failed");
		goto fail9;
	}

	err = sti7109_cmd_get_fw_version(sti7109, &fw_version);
	if (!err) {
		printk(KERN_INFO "SAA716x FF firmware version %d.%d.%d\n",
			(fw_version >> 16) & 0xFF, (fw_version >> 8) & 0xFF,
			fw_version & 0xFF);
	}

	err = saa716x_ir_init(saa716x);
	if (err)
		goto fail9;

	return 0;

fail9:
	saa716x_ff_osd_exit(saa716x);
fail8:
	saa716x_ff_audio_exit(saa716x);
fail7:
	saa716x_ff_video_exit(saa716x);
fail6:
	saa716x_dvb_exit(saa716x);
fail5:
	SAA716x_EPWR(MSI, MSI_INT_ENA_CLR_H, MSI_INT_EXTINT_0);

	/* disable board power */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_POWER_ENABLE, 0);

	vfree(sti7109->iobuf);
fail4:
	kfree(sti7109);
fail3:
	saa716x_i2c_exit(saa716x);
fail2:
	saa716x_pci_exit(saa716x);
fail1:
	kfree(saa716x);
fail0:
	return err;
}

static void saa716x_ff_pci_remove(struct pci_dev *pdev)
{
	struct saa716x_dev *saa716x = pci_get_drvdata(pdev);
	struct sti7109_dev *sti7109 = saa716x->priv;

	saa716x_ir_exit(saa716x);

	saa716x_ff_osd_exit(saa716x);

	saa716x_ff_audio_exit(saa716x);

	saa716x_ff_video_exit(saa716x);

	saa716x_dvb_exit(saa716x);

	SAA716x_EPWR(MSI, MSI_INT_ENA_CLR_H, MSI_INT_EXTINT_0);

	/* disable board power */
	saa716x_gpio_write(saa716x, TT_PREMIUM_GPIO_POWER_ENABLE, 0);

	vfree(sti7109->iobuf);

	saa716x->priv = NULL;
	kfree(sti7109);

	saa716x_i2c_exit(saa716x);
	saa716x_pci_exit(saa716x);
	kfree(saa716x);
}

static void demux_worker(unsigned long data)
{
	struct saa716x_fgpi_stream_port *fgpi_entry = (struct saa716x_fgpi_stream_port *)data;
	struct saa716x_dev *saa716x = fgpi_entry->saa716x;
	struct dvb_demux *demux;
	u32 fgpi_index;
	u32 i;
	u32 write_index;

	fgpi_index = fgpi_entry->dma_channel - 6;
	demux = NULL;
	for (i = 0; i < saa716x->config->adapters; i++) {
		if (saa716x->config->adap_config[i].ts_port == fgpi_index) {
			demux = &saa716x->saa716x_adap[i].demux;
			break;
		}
	}
	if (demux == NULL) {
		printk(KERN_ERR "%s: unexpected channel %u\n",
		       __func__, fgpi_entry->dma_channel);
		return;
	}

	write_index = saa716x_fgpi_get_write_index(saa716x, fgpi_index);
	if (write_index < 0)
		return;

	dprintk(SAA716x_DEBUG, 1, "dma buffer = %d", write_index);

	if (write_index == fgpi_entry->read_index) {
		printk(KERN_DEBUG "%s: called but nothing to do\n", __func__);
		return;
	}

	do {
		u8 *data = (u8 *)fgpi_entry->dma_buf[fgpi_entry->read_index].mem_virt;

		dma_sync_sg_for_cpu(&saa716x->pdev->dev,
			fgpi_entry->dma_buf[fgpi_entry->read_index].sg_list,
			fgpi_entry->dma_buf[fgpi_entry->read_index].list_len,
			DMA_FROM_DEVICE);

		dvb_dmx_swfilter(demux, data, 348 * 188);

		fgpi_entry->read_index = (fgpi_entry->read_index + 1) & 7;
	} while (write_index != fgpi_entry->read_index);
}

static irqreturn_t saa716x_ff_pci_irq(int irq, void *dev_id)
{
	struct saa716x_dev *saa716x	= (struct saa716x_dev *) dev_id;
	struct sti7109_dev *sti7109;
	u32 msiStatusL;
	u32 msiStatusH;
	u32 phiISR;

	if (unlikely(saa716x == NULL)) {
		printk("%s: saa716x=NULL", __func__);
		return IRQ_NONE;
	}
	sti7109 = saa716x->priv;
	if (unlikely(sti7109 == NULL)) {
		printk("%s: sti7109=NULL", __func__);
		return IRQ_NONE;
	}
	if (sti7109->int_count_enable)
		sti7109->total_int_count++;
#if 0
	dprintk(SAA716x_DEBUG, 1, "VI STAT 0=<%02x> 1=<%02x>, CTL 1=<%02x> 2=<%02x>",
		SAA716x_EPRD(VI0, INT_STATUS),
		SAA716x_EPRD(VI1, INT_STATUS),
		SAA716x_EPRD(VI0, INT_ENABLE),
		SAA716x_EPRD(VI1, INT_ENABLE));

	dprintk(SAA716x_DEBUG, 1, "FGPI STAT 0=<%02x> 1=<%02x>, CTL 1=<%02x> 2=<%02x>",
		SAA716x_EPRD(FGPI0, INT_STATUS),
		SAA716x_EPRD(FGPI1, INT_STATUS),
		SAA716x_EPRD(FGPI0, INT_ENABLE),
		SAA716x_EPRD(FGPI0, INT_ENABLE));

	dprintk(SAA716x_DEBUG, 1, "FGPI STAT 2=<%02x> 3=<%02x>, CTL 2=<%02x> 3=<%02x>",
		SAA716x_EPRD(FGPI2, INT_STATUS),
		SAA716x_EPRD(FGPI3, INT_STATUS),
		SAA716x_EPRD(FGPI2, INT_ENABLE),
		SAA716x_EPRD(FGPI3, INT_ENABLE));

	dprintk(SAA716x_DEBUG, 1, "AI STAT 0=<%02x> 1=<%02x>, CTL 0=<%02x> 1=<%02x>",
		SAA716x_EPRD(AI0, AI_STATUS),
		SAA716x_EPRD(AI1, AI_STATUS),
		SAA716x_EPRD(AI0, AI_CTL),
		SAA716x_EPRD(AI1, AI_CTL));

	dprintk(SAA716x_DEBUG, 1, "MSI STAT L=<%02x> H=<%02x>, CTL L=<%02x> H=<%02x>",
		SAA716x_EPRD(MSI, MSI_INT_STATUS_L),
		SAA716x_EPRD(MSI, MSI_INT_STATUS_H),
		SAA716x_EPRD(MSI, MSI_INT_ENA_L),
		SAA716x_EPRD(MSI, MSI_INT_ENA_H));

	dprintk(SAA716x_DEBUG, 1, "I2C STAT 0=<%02x> 1=<%02x>, CTL 0=<%02x> 1=<%02x>",
		SAA716x_EPRD(I2C_A, INT_STATUS),
		SAA716x_EPRD(I2C_B, INT_STATUS),
		SAA716x_EPRD(I2C_A, INT_ENABLE),
		SAA716x_EPRD(I2C_B, INT_ENABLE));

	dprintk(SAA716x_DEBUG, 1, "DCS STAT=<%02x>, CTL=<%02x>",
		SAA716x_EPRD(DCS, DCSC_INT_STATUS),
		SAA716x_EPRD(DCS, DCSC_INT_ENABLE));
#endif
	msiStatusL = SAA716x_EPRD(MSI, MSI_INT_STATUS_L);
	SAA716x_EPWR(MSI, MSI_INT_STATUS_CLR_L, msiStatusL);
	msiStatusH = SAA716x_EPRD(MSI, MSI_INT_STATUS_H);
	SAA716x_EPWR(MSI, MSI_INT_STATUS_CLR_H, msiStatusH);

	if (msiStatusL) {
		if (msiStatusL & MSI_INT_TAGACK_VI0_0) {
			if (sti7109->int_count_enable)
				sti7109->vi_int_count[0]++;
			tasklet_schedule(&saa716x->vip[0].tasklet);
		}
		if (msiStatusL & MSI_INT_TAGACK_FGPI_2) {
			if (sti7109->int_count_enable)
				sti7109->fgpi_int_count[2]++;
			tasklet_schedule(&saa716x->fgpi[2].tasklet);
		}
		if (msiStatusL & MSI_INT_TAGACK_FGPI_3) {
			if (sti7109->int_count_enable)
				sti7109->fgpi_int_count[3]++;
			tasklet_schedule(&saa716x->fgpi[3].tasklet);
		}
	}
	if (msiStatusH) {
		//dprintk(SAA716x_INFO, 1, "msiStatusH: %08X", msiStatusH);
	}

	if (msiStatusH & MSI_INT_I2CINT_0) {
		if (sti7109->int_count_enable)
			sti7109->i2c_int_count[0]++;
		saa716x->i2c[0].i2c_op = 0;
		wake_up(&saa716x->i2c[0].i2c_wq);
	}
	if (msiStatusH & MSI_INT_I2CINT_1) {
		if (sti7109->int_count_enable)
			sti7109->i2c_int_count[1]++;
		saa716x->i2c[1].i2c_op = 0;
		wake_up(&saa716x->i2c[1].i2c_wq);
	}

	if (msiStatusH & MSI_INT_EXTINT_0) {

		phiISR = SAA716x_EPRD(PHI_1, FPGA_ADDR_EMI_ISR);
		//dprintk(SAA716x_INFO, 1, "interrupt status register: %08X", phiISR);

		if (sti7109->int_count_enable) {
			int i;
			sti7109->ext_int_total_count++;
			for (i = 0; i < 16; i++)
				if (phiISR & (1 << i))
					sti7109->ext_int_source_count[i]++;
		}

		if (phiISR & ISR_CMD_MASK) {

			u32 value;
			u32 length;
			/*dprintk(SAA716x_INFO, 1, "CMD interrupt source");*/

			value = SAA716x_EPRD(PHI_1, ADDR_CMD_DATA);
			value = __cpu_to_be32(value);
			length = (value >> 16) + 2;

			/*dprintk(SAA716x_INFO, 1, "CMD length: %d", length);*/

			if (length > MAX_RESULT_LEN) {
				dprintk(SAA716x_ERROR, 1, "CMD length %d > %d", length, MAX_RESULT_LEN);
				length = MAX_RESULT_LEN;
			}

			saa716x_phi_read(saa716x, ADDR_CMD_DATA, sti7109->result_data, length);
			sti7109->result_len = length;
			sti7109->result_avail = 1;
			wake_up(&sti7109->result_avail_wq);

			phiISR &= ~ISR_CMD_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_CMD_MASK);
		}

		if (phiISR & ISR_READY_MASK) {
			/*dprintk(SAA716x_INFO, 1, "READY interrupt source");*/
			sti7109->cmd_ready = 1;
			wake_up(&sti7109->cmd_ready_wq);
			phiISR &= ~ISR_READY_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_READY_MASK);
		}

		if (phiISR & ISR_OSD_CMD_MASK) {

			u32 value;
			u32 length;
			/*dprintk(SAA716x_INFO, 1, "OSD CMD interrupt source");*/

			value = SAA716x_EPRD(PHI_1, ADDR_OSD_CMD_DATA);
			value = __cpu_to_be32(value);
			length = (value >> 16) + 2;

			/*dprintk(SAA716x_INFO, 1, "OSD CMD length: %d", length);*/

			if (length > MAX_RESULT_LEN) {
				dprintk(SAA716x_ERROR, 1, "OSD CMD length %d > %d", length, MAX_RESULT_LEN);
				length = MAX_RESULT_LEN;
			}

			saa716x_phi_read(saa716x, ADDR_OSD_CMD_DATA, sti7109->osd_result_data, length);
			sti7109->osd_result_len = length;
			sti7109->osd_result_avail = 1;
			wake_up(&sti7109->osd_result_avail_wq);

			phiISR &= ~ISR_OSD_CMD_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_OSD_CMD_MASK);
		}

		if (phiISR & ISR_OSD_READY_MASK) {
			/*dprintk(SAA716x_INFO, 1, "OSD_READY interrupt source");*/
			sti7109->osd_cmd_ready = 1;
			wake_up(&sti7109->osd_cmd_ready_wq);
			phiISR &= ~ISR_OSD_READY_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_OSD_READY_MASK);
		}

		if (phiISR & ISR_BLOCK_MASK) {
			/*dprintk(SAA716x_INFO, 1, "BLOCK interrupt source");*/
			sti7109->block_done = 1;
			wake_up(&sti7109->block_done_wq);
			phiISR &= ~ISR_BLOCK_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_BLOCK_MASK);
		}

		if (phiISR & ISR_DATA_MASK) {
			/*dprintk(SAA716x_INFO, 1, "DATA interrupt source");*/
			sti7109->data_ready = 1;
			wake_up(&sti7109->data_ready_wq);
			phiISR &= ~ISR_DATA_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_DATA_MASK);
		}

		if (phiISR & ISR_BOOT_FINISH_MASK) {
			/*dprintk(SAA716x_INFO, 1, "BOOT FINISH interrupt source");*/
			sti7109->boot_finished = 1;
			wake_up(&sti7109->boot_finish_wq);
			phiISR &= ~ISR_BOOT_FINISH_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_BOOT_FINISH_MASK);
		}

		if (phiISR & ISR_AUDIO_PTS_MASK) {
			u8 data[8];

			saa716x_phi_read(saa716x, ADDR_AUDIO_PTS, data, 8);
			sti7109->audio_pts = (((u64) data[3] & 0x01) << 32)
					    | ((u64) data[4] << 24)
					    | ((u64) data[5] << 16)
					    | ((u64) data[6] << 8)
					    | ((u64) data[7]);

			phiISR &= ~ISR_AUDIO_PTS_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_AUDIO_PTS_MASK);

			/*dprintk(SAA716x_INFO, 1, "AUDIO PTS: %llX", sti7109->audio_pts);*/
		}

		if (phiISR & ISR_VIDEO_PTS_MASK) {
			u8 data[8];

			saa716x_phi_read(saa716x, ADDR_VIDEO_PTS, data, 8);
			sti7109->video_pts = (((u64) data[3] & 0x01) << 32)
					    | ((u64) data[4] << 24)
					    | ((u64) data[5] << 16)
					    | ((u64) data[6] << 8)
					    | ((u64) data[7]);

			phiISR &= ~ISR_VIDEO_PTS_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_VIDEO_PTS_MASK);

			/*dprintk(SAA716x_INFO, 1, "VIDEO PTS: %llX", sti7109->video_pts);*/
		}

		if (phiISR & ISR_CURRENT_STC_MASK) {
			u8 data[8];

			saa716x_phi_read(saa716x, ADDR_CURRENT_STC, data, 8);
			sti7109->current_stc = (((u64) data[3] & 0x01) << 32)
					      | ((u64) data[4] << 24)
					      | ((u64) data[5] << 16)
					      | ((u64) data[6] << 8)
					      | ((u64) data[7]);

			phiISR &= ~ISR_CURRENT_STC_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_CURRENT_STC_MASK);

			/*dprintk(SAA716x_INFO, 1, "CURRENT STC: %llu", sti7109->current_stc);*/
		}

		if (phiISR & ISR_REMOTE_EVENT_MASK) {
			u8 data[4];
			u32 remote_event;

			saa716x_phi_read(saa716x, ADDR_REMOTE_EVENT, data, 4);
			remote_event = (data[3] << 24)
				     | (data[2] << 16)
				     | (data[1] << 8)
				     | (data[0]);
			memset(data, 0, sizeof(data));
			saa716x_phi_write(saa716x, ADDR_REMOTE_EVENT, data, 4);

			phiISR &= ~ISR_REMOTE_EVENT_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_REMOTE_EVENT_MASK);

			if (remote_event == 0) {
				dprintk(SAA716x_ERROR, 1, "REMOTE EVENT: %X ignored", remote_event);
			} else {
				dprintk(SAA716x_INFO, 1, "REMOTE EVENT: %X", remote_event);
				saa716x_ir_handler(saa716x, remote_event);
			}
		}

		if (phiISR & ISR_DVO_FORMAT_MASK) {
			u8 data[4];
			u32 format;

			saa716x_phi_read(saa716x, ADDR_DVO_FORMAT, data, 4);
			format = (data[0] << 24)
			       | (data[1] << 16)
			       | (data[2] << 8)
			       | (data[3]);

			phiISR &= ~ISR_DVO_FORMAT_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_DVO_FORMAT_MASK);

			dprintk(SAA716x_INFO, 1, "DVO FORMAT CHANGE: %u", format);
			sti7109->video_format = format;
		}

		if (phiISR & ISR_LOG_MESSAGE_MASK) {
			char message[SIZE_LOG_MESSAGE_DATA];

			saa716x_phi_read(saa716x, ADDR_LOG_MESSAGE, message,
					 SIZE_LOG_MESSAGE_DATA);

			phiISR &= ~ISR_LOG_MESSAGE_MASK;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, ISR_LOG_MESSAGE_MASK);

			dprintk(SAA716x_INFO, 1, "LOG MESSAGE: %.*s",
				SIZE_LOG_MESSAGE_DATA, message);
		}

		if (phiISR & ISR_FIFO1_EMPTY_MASK) {
			u32 fifoCtrl;

			/*dprintk(SAA716x_INFO, 1, "FIFO EMPTY interrupt source");*/
			fifoCtrl = SAA716x_EPRD(PHI_1, FPGA_ADDR_FIFO_CTRL);
			fifoCtrl &= ~0x4;
			SAA716x_EPWR(PHI_1, FPGA_ADDR_FIFO_CTRL, fifoCtrl);
			queue_work(sti7109->fifo_workq, &sti7109->fifo_work);
			phiISR &= ~ISR_FIFO1_EMPTY_MASK;
		}

		if (phiISR) {
			dprintk(SAA716x_INFO, 1, "unknown interrupt source");
			SAA716x_EPWR(PHI_1, FPGA_ADDR_EMI_ICLR, phiISR);
		}
	}

	if (sti7109->int_count_enable) {
		if (jiffies - sti7109->last_int_ticks >= HZ) {
			dprintk(SAA716x_INFO, 1,
				"int count: t: %d, v: %d %d, f:%d %d %d %d, i:%d %d,"
				"e: %d (%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d)",
				sti7109->total_int_count,
				sti7109->vi_int_count[0],
				sti7109->vi_int_count[1],
				sti7109->fgpi_int_count[0],
				sti7109->fgpi_int_count[1],
				sti7109->fgpi_int_count[2],
				sti7109->fgpi_int_count[3],
				sti7109->i2c_int_count[0],
				sti7109->i2c_int_count[1],
				sti7109->ext_int_total_count,
				sti7109->ext_int_source_count[0],
				sti7109->ext_int_source_count[1],
				sti7109->ext_int_source_count[2],
				sti7109->ext_int_source_count[3],
				sti7109->ext_int_source_count[4],
				sti7109->ext_int_source_count[5],
				sti7109->ext_int_source_count[6],
				sti7109->ext_int_source_count[7],
				sti7109->ext_int_source_count[8],
				sti7109->ext_int_source_count[9],
				sti7109->ext_int_source_count[10],
				sti7109->ext_int_source_count[11],
				sti7109->ext_int_source_count[12],
				sti7109->ext_int_source_count[13],
				sti7109->ext_int_source_count[14],
				sti7109->ext_int_source_count[15]);
			sti7109->total_int_count = 0;
			memset(sti7109->vi_int_count, 0, sizeof(sti7109->vi_int_count));
			memset(sti7109->fgpi_int_count, 0, sizeof(sti7109->fgpi_int_count));
			memset(sti7109->i2c_int_count, 0, sizeof(sti7109->i2c_int_count));
			sti7109->ext_int_total_count = 0;
			memset(sti7109->ext_int_source_count, 0, sizeof(sti7109->ext_int_source_count));
			sti7109->last_int_ticks = jiffies;
		}
	}
	return IRQ_HANDLED;
}

#define SAA716x_MODEL_S2_6400_DUAL	"Technotrend S2 6400 Dual S2 Premium"
#define SAA716x_DEV_S2_6400_DUAL	"2x DVB-S/S2 + Hardware decode"

static struct stv090x_config tt6400_stv090x_config = {
	.device			= STV0900,
	.demod_mode		= STV090x_DUAL,
	.clk_mode		= STV090x_CLK_EXT,

	.xtal			= 13500000,
	.address		= 0x68,

	.ts1_mode		= STV090x_TSMODE_SERIAL_CONTINUOUS,
	.ts2_mode		= STV090x_TSMODE_SERIAL_CONTINUOUS,
	.ts1_clk		= 135000000,
	.ts2_clk		= 135000000,

	.repeater_level		= STV090x_RPTLEVEL_16,

	.tuner_init		= NULL,
	.tuner_set_mode		= NULL,
	.tuner_set_frequency	= NULL,
	.tuner_get_frequency	= NULL,
	.tuner_set_bandwidth	= NULL,
	.tuner_get_bandwidth	= NULL,
	.tuner_set_bbgain	= NULL,
	.tuner_get_bbgain	= NULL,
	.tuner_set_refclk	= NULL,
	.tuner_get_status	= NULL,
};

static struct stv6110x_config tt6400_stv6110x_config = {
	.addr			= 0x60,
	.refclk			= 27000000,
	.clk_div		= 2,
};

static struct isl6423_config tt6400_isl6423_config[2] = {
	{
		.current_max		= SEC_CURRENT_515m,
		.curlim			= SEC_CURRENT_LIM_ON,
		.mod_extern		= 1,
		.addr			= 0x09,
	},
	{
		.current_max		= SEC_CURRENT_515m,
		.curlim			= SEC_CURRENT_LIM_ON,
		.mod_extern		= 1,
		.addr			= 0x08,
	}
};


static int saa716x_s26400_frontend_attach(struct saa716x_adapter *adapter, int count)
{
	struct saa716x_dev *saa716x	= adapter->saa716x;
	struct saa716x_i2c *i2c		= saa716x->i2c;
	struct i2c_adapter *i2c_adapter	= &i2c[SAA716x_I2C_BUS_A].i2c_adapter;

	dprintk(SAA716x_DEBUG, 1, "Adapter (%d) SAA716x frontend Init", count);
	dprintk(SAA716x_DEBUG, 1, "Adapter (%d) Device ID=%02x", count, saa716x->pdev->subsystem_device);

	if (count == 0 || count == 1) {
		adapter->fe = dvb_attach(stv090x_attach,
					 &tt6400_stv090x_config,
					 i2c_adapter,
					 STV090x_DEMODULATOR_0 + count);

		if (adapter->fe) {
			struct stv6110x_devctl *ctl;
			ctl = dvb_attach(stv6110x_attach,
					 adapter->fe,
					 &tt6400_stv6110x_config,
					 i2c_adapter);

			tt6400_stv090x_config.tuner_init	  = ctl->tuner_init;
			tt6400_stv090x_config.tuner_sleep	  = ctl->tuner_sleep;
			tt6400_stv090x_config.tuner_set_mode	  = ctl->tuner_set_mode;
			tt6400_stv090x_config.tuner_set_frequency = ctl->tuner_set_frequency;
			tt6400_stv090x_config.tuner_get_frequency = ctl->tuner_get_frequency;
			tt6400_stv090x_config.tuner_set_bandwidth = ctl->tuner_set_bandwidth;
			tt6400_stv090x_config.tuner_get_bandwidth = ctl->tuner_get_bandwidth;
			tt6400_stv090x_config.tuner_set_bbgain	  = ctl->tuner_set_bbgain;
			tt6400_stv090x_config.tuner_get_bbgain	  = ctl->tuner_get_bbgain;
			tt6400_stv090x_config.tuner_set_refclk	  = ctl->tuner_set_refclk;
			tt6400_stv090x_config.tuner_get_status	  = ctl->tuner_get_status;

			if (count == 1) {
				/* call the init function once to initialize
				   tuner's clock output divider and demod's
				   master clock */
				/* The second tuner drives the STV0900 so
				   call it only for adapter 1 */
				if (adapter->fe->ops.init)
					adapter->fe->ops.init(adapter->fe);
			}

			dvb_attach(isl6423_attach,
				   adapter->fe,
				   i2c_adapter,
				   &tt6400_isl6423_config[count]);

		}
	}
	return 0;
}

static struct saa716x_config saa716x_s26400_config = {
	.model_name		= SAA716x_MODEL_S2_6400_DUAL,
	.dev_type		= SAA716x_DEV_S2_6400_DUAL,
	.boot_mode		= SAA716x_EXT_BOOT,
	.adapters		= 2,
	.frontend_attach	= saa716x_s26400_frontend_attach,
	.irq_handler		= saa716x_ff_pci_irq,
	.i2c_rate		= SAA716x_I2C_RATE_100,
	.i2c_mode		= SAA716x_I2C_MODE_IRQ_BUFFERED,

	.adap_config		= {
		{
			/* Adapter 0 */
			.ts_port = 2,
			.worker = demux_worker
		},{
			/* Adapter 1 */
			.ts_port = 3,
			.worker = demux_worker
		}
	}
};


static struct pci_device_id saa716x_ff_pci_table[] = {

	MAKE_ENTRY(TECHNOTREND, S2_6400_DUAL_S2_PREMIUM_DEVEL, SAA7160, &saa716x_s26400_config),  /* S2 6400 Dual development version */
	MAKE_ENTRY(TECHNOTREND, S2_6400_DUAL_S2_PREMIUM_PROD, SAA7160, &saa716x_s26400_config), /* S2 6400 Dual production version */
	{ }
};
MODULE_DEVICE_TABLE(pci, saa716x_ff_pci_table);

static struct pci_driver saa716x_ff_pci_driver = {
	.name			= DRIVER_NAME,
	.id_table		= saa716x_ff_pci_table,
	.probe			= saa716x_ff_pci_probe,
	.remove			= saa716x_ff_pci_remove,
};

module_pci_driver(saa716x_ff_pci_driver);

MODULE_DESCRIPTION("SAA716x FF driver");
MODULE_AUTHOR("Manu Abraham");
MODULE_LICENSE("GPL");
