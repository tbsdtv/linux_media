/*
    TurboSight TBS PCIE DVB driver
    Copyright (C) 2017 www.tbsdtv.com
*/

#include <linux/pci.h>
#include "tbs_pcie.h"
#include "tbs_pcie-reg.h"

static void tbs_adapters_init(struct tbs_pcie_dev *dev);
static void tbs_hdmi_video_param(struct tbs_pcie_dev *dev,int index);
static void tbs_sdi_video_param(struct tbs_pcie_dev *dev,int index);

struct workqueue_struct *wq;

u8 fw7611[]=
{
//	0x98, 0xFF, 0x80 , //I2C reset
	0x98, 0xF4, 0x80 , //CEC
	0x98, 0xF5, 0x7C , //INFOFRAME
	0x98, 0xF8, 0x4C , //DPLL
	0x98, 0xF9, 0x64 ,// KSV
	0x98, 0xFA, 0x6C , //EDID
	0x98, 0xFB, 0x68, // HDMI
	0x98, 0xFD, 0x44 ,// CP
	0x98, 0x01, 0x06 , //Prim_Mode =110b HDMI-GR
	0x98, 0x02, 0xF5 , //Auto CSC, YCrCb out, Set op_656 bit
	0x98, 0x03, 0x80 , //24 bit SDR 444 Mode 0
	0x98, 0x05, 0x28 , //AV Codes Off  28
	//0x98, 0x06, 0xA4 ,// A4 Invert VS,HS pins
	0x98, 0x06, 0x26, //eric mark, field;
	0x98, 0x0B, 0x44 , //Power up part
	0x98, 0x0C, 0x42 , //Power up part
	0x98, 0x14, 0x7F , //Max Drive Strength
	0x98, 0x15, 0x80 , //Disable Tristate of Pins
	0x98, 0x19, 0x83 , //LLC DLL phase
	0x98, 0x33, 0x40 , //LLC DLL enable
//	0x68, 0x48, 0x40 ,
	0x44, 0xBA, 0x01 ,// Set HDMI FreeRun
	0x64, 0x40, 0x81 , //Disable HDCP 1.1 features
	0x68, 0x9B, 0x03 , //ADI recommended setting
	0x68, 0xC1, 0x01 , //ADI recommended setting
	0x68, 0xC2, 0x01 ,// ADI recommended setting
	0x68, 0xC3, 0x01 , //ADI recommended setting
	0x68, 0xC4, 0x01 , //ADI recommended setting
	0x68, 0xC5, 0x01 , //ADI recommended setting
	0x68, 0xC6, 0x01 , //ADI recommended setting
	0x68, 0xC7, 0x01 , //ADI recommended setting
	0x68, 0xC8, 0x01 , //ADI recommended setting
	0x68, 0xC9, 0x01 ,// ADI recommended setting
	0x68, 0xCA, 0x01 , //ADI recommended setting
	0x68, 0xCB, 0x01 , //ADI recommended setting
	0x68, 0xCC, 0x01 ,// ADI recommended setting
	0x68, 0x00, 0x00 , //Set HDMI Input Port A
	0x68, 0x83, 0xFE , //Enable clock terminator for port A
	0x68, 0x6F, 0x0C ,// ADI recommended setting
	0x68, 0x85, 0x1F , //ADI recommended setting
	0x68, 0x87, 0x70 , //ADI recommended setting
	0x68, 0x8D, 0x04 , //LFG
	0x68, 0x8E, 0x1E , //HFG
	0x68, 0x1A, 0x8A , //unmute audio
	0x68, 0x57, 0xDA , //ADI recommended setting
	0x68, 0x58, 0x01 , //ADI recommended setting
	0x68, 0x03, 0x98 , // DIS_I2C_ZERO_COMPR
	0x68, 0x75, 0x10 , //DDC drive strength

	0xff};

static int i2c_read_reg(struct i2c_adapter *adapter, u8 adr, u8 reg, u8 *val, int len)
{
	struct i2c_msg msgs[2] = {{.addr = adr, .flags =0,
			.buf = &reg, .len =1},
			{.addr =adr, .flags = I2C_M_RD,
			.buf = val, .len = len}};
	return (i2c_transfer(adapter, msgs,2) == 2) ? 0 : -1;
	
}

static int i2c_write_reg(struct i2c_adapter *adapter, u8 adr, u8 *val, int len)
{

	struct i2c_msg msg[1] = {{.addr = adr, .flags =0,
			.buf = val, .len =len}};
	return (i2c_transfer(adapter, msg,1) == 1) ? 0 : -1;
	
}
void i2c_write_tab_new(struct i2c_adapter *adapter, u8 *script)
{
	u8 temp[2];
	do{	
		temp[0] = *(script+1);
		temp[1] = *(script+2);
		i2c_write_reg(adapter,*(script),temp,2 );
		script += 3;
	}while(*script != 0xff);
}

static int tbs_vidioc_querycap(struct file *file, void *priv, struct v4l2_capability *cap)
{
	struct tbs_video *videodev = video_drvdata(file);
	strcpy(cap->driver, KBUILD_MODNAME);
	sprintf(cap->card, "pcie video %d",(videodev->index-1)?1:0);
	strcpy(cap->bus_info, "pcie");
	cap->device_caps =	V4L2_CAP_VIDEO_CAPTURE |V4L2_CAP_STREAMING;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;
	return 0;
}
static int tbs_vidioc_enum_fmt_vid_cap(struct file *file, void *priv_fh,struct v4l2_fmtdesc *f)
{
	switch (f->index) {
	case 0:
		strlcpy(f->description, "YUV 4:2:2", sizeof(f->description));
		f->pixelformat = V4L2_PIX_FMT_UYVY;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int tbs_vidioc_g_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *fmt)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct v4l2_pix_format *pix = &fmt->fmt.pix;

	if(videodev->width==0 || videodev->height==0 )
		return -1;

	pix->width = videodev->width;
	pix->height = videodev->height;
	pix->pixelformat = V4L2_PIX_FMT_UYVY;
	pix->field = V4L2_FIELD_ALTERNATE;
	pix->bytesperline = videodev->width*2;
	pix->sizeimage = 2 * videodev->width * videodev->height;
	/* Just a guess */
	pix->colorspace = V4L2_COLORSPACE_SMPTE170M;
	return 0;
}

static int tbs_vidioc_try_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *fmt)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct v4l2_pix_format *pix = &fmt->fmt.pix;

	if(videodev->width==0 || videodev->height==0 )
		return -1;

	pix->height = videodev->height;
	pix->width = videodev->width ;
	pix->field = V4L2_FIELD_ALTERNATE;

	pix->pixelformat = V4L2_PIX_FMT_UYVY;
	pix->bytesperline = videodev->width*2;
	pix->sizeimage = 2 * videodev->width * videodev->height;

	videodev->dmabuf[1].size = videodev->dmabuf[0].size = pix->sizeimage;
	
	/* Just a guess */
	pix->colorspace = V4L2_COLORSPACE_SMPTE170M;
	return 0;
}
static int vidioc_s_fmt_vid_cap(struct file *file, void *priv,struct v4l2_format *f)
{
	struct tbs_video *videodev = video_drvdata(file);
	int err;
	err = tbs_vidioc_try_fmt_vid_cap(file, priv, f);
	if (0 != err)
		return err;
	videodev->pixfmt     = f->fmt.pix.pixelformat;
	videodev->width      = f->fmt.pix.width;
	videodev->height     = f->fmt.pix.height;
	return 0;
}
static int tbs_vidioc_g_std(struct file *file, void *priv, v4l2_std_id *tvnorms)
{
	struct tbs_video *videodev = video_drvdata(file);
	*tvnorms = videodev->std;
	return 0;
}

static int tbs_vidioc_s_std(struct file *file, void *priv,v4l2_std_id tvnorms)
{
	struct tbs_video *videodev = video_drvdata(file);
	videodev->std = tvnorms;
	return 0;
}

int tbs_vidioc_g_parm(struct file *file,void *fh, struct v4l2_streamparm *setfps)
{
	struct tbs_video *videodev = video_drvdata(file);
    	setfps->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
   	setfps->parm.capture.timeperframe.numerator=1;
    	setfps->parm.capture.timeperframe.denominator=videodev->fps;
	return 0;	
}

static int tbs_vidioc_enum_input(struct file *file, void *priv,struct v4l2_input *i)
{
	if(i->index)
		return -EINVAL;
	i->type = V4L2_INPUT_TYPE_CAMERA;
	strcpy(i->name, KBUILD_MODNAME);
	i->std = V4L2_STD_NTSC_M;	
	return 0;
}

static int tbs_vidioc_g_input(struct file *file, void *priv, unsigned int *i)
{
	*i = 0;
	return 0;
}

static int tbs_vidioc_s_input(struct file *file, void *priv, unsigned int i)
{
	return i ? -EINVAL : 0;
}
static int vidioc_log_status(struct file *file, void *priv)
{
	return 0;
}

static ssize_t tbs_read(struct file *file,char *buf,size_t count, loff_t *ppos)
{
	return 0;
		
}

static int tbs_open(struct file *file)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct pci_dev *pci = videodev->dev->pdev;
	u32 temp1,temp2;
	u32 h_para,v_para;
	u32 frame_ps,pori;
	struct tbs_pcie_dev *dev = videodev->dev;
	if(pci->subsystem_vendor == 0x6324) //tbs6324 sdi
	{
		temp1= TBS_PCIE_READ(0x0,40);
		temp2 =TBS_PCIE_READ(0x0,44);
		h_para = ((temp1 & 0xff)<<8) + ((temp1 & 0xff00)>>8);
		v_para = ((temp1 & 0xff0000)>>8) + ((temp1 & 0xff000000)>>24);
		frame_ps = temp2 &0xff;
		pori = (temp2>>8) & 0xff;
		

		printk("fpga get para: %x, %x == v:%d, h:%d, frame:%d, P:%d\n", temp1,temp2,v_para,h_para,frame_ps,pori);

		tbs_sdi_video_param(videodev->dev, videodev->index>>1);
	}
	else //hdmi
		tbs_hdmi_video_param(videodev->dev, videodev->index>>1);
	if(videodev->width==0 || videodev->height==0 )
		return -1;
	return 0;
		
}

static int tbs_vidioc_get_ctrl(struct file *file, void *fh,
			        struct v4l2_tbs_data * data)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct tbs_pcie_dev *dev = videodev->dev;
	data->value  = TBS_PCIE_READ(data->baseaddr, data->reg);
	printk("read :baseaddr=0x%x, reg=0x%x, value=0x%x\n", data->baseaddr, data->reg, data->value);
	return 0;
}
static int tbs_vidioc_set_ctrl(struct file *file, void *fh,
			        struct v4l2_tbs_data * data)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct tbs_pcie_dev *dev = videodev->dev;
	printk("write: baseaddr=0x%x, reg=0x%x, value=0x%x\n", data->baseaddr, data->reg, data->value);
	TBS_PCIE_WRITE(data->baseaddr,data->reg,data->value);
	return 0;
}

static const struct v4l2_file_operations tbs_fops = {
	.owner		= THIS_MODULE,
	.open		= tbs_open,//v4l2_fh_open,
	.release	= vb2_fop_release,
	.read		= tbs_read,//vb2_fop_read,
	.poll		= vb2_fop_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap           = vb2_fop_mmap,
};


static const struct v4l2_ioctl_ops tbs_ioctl_fops = {
	.vidioc_querycap = tbs_vidioc_querycap,
	.vidioc_enum_fmt_vid_cap = tbs_vidioc_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap = tbs_vidioc_g_fmt_vid_cap,
	.vidioc_try_fmt_vid_cap = tbs_vidioc_try_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap = vidioc_s_fmt_vid_cap,
	.vidioc_reqbufs       = vb2_ioctl_reqbufs,
	.vidioc_prepare_buf   = vb2_ioctl_prepare_buf,
	.vidioc_create_bufs   = vb2_ioctl_create_bufs,
	.vidioc_querybuf      = vb2_ioctl_querybuf,
	.vidioc_qbuf          = vb2_ioctl_qbuf,
	.vidioc_dqbuf         = vb2_ioctl_dqbuf,
	.vidioc_streamon      = vb2_ioctl_streamon,
	.vidioc_streamoff     = vb2_ioctl_streamoff,
	.vidioc_g_std = tbs_vidioc_g_std,
	.vidioc_s_std = tbs_vidioc_s_std,
	.vidioc_enum_input = tbs_vidioc_enum_input,
	.vidioc_g_input = tbs_vidioc_g_input,
	.vidioc_s_input = tbs_vidioc_s_input,
	.vidioc_log_status = vidioc_log_status,
	.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
	.vidioc_g_parm = tbs_vidioc_g_parm,
	.vidioc_tbs_g_ctrls = tbs_vidioc_get_ctrl,
	.vidioc_tbs_s_ctrls = tbs_vidioc_set_ctrl,
};
//long (*vidioc_default)(struct file *file, void *fh,
//			       bool valid_prio, unsigned int cmd, void *arg);
/* calc max # of buffers from size (must not exceed the 4MB virtual
 * address space per DMA channel) */
static int tbs_buffer_count(unsigned int size, unsigned int count)
{
	unsigned int maxcount;

	maxcount = (8 * 1024 * 1024) / roundup(size, PAGE_SIZE);
	if (count > maxcount)
		count = maxcount;
	return count;
}

static int tbs_queue_setup(struct vb2_queue *q,
			   unsigned int *num_buffers, unsigned int *num_planes,
			   unsigned int sizes[], struct device *alloc_devs[])
{
	struct tbs_video *videodev = q->drv_priv;
	unsigned tot_bufs = q->num_buffers + *num_buffers;
	unsigned size = 2* videodev->width * videodev->height; // 16bit

	videodev->dmabuf[1].size = videodev->dmabuf[0].size = size;

	if (tot_bufs < 2)
		tot_bufs = 2;
	tot_bufs = tbs_buffer_count(size, tot_bufs);
	*num_buffers = tot_bufs - q->num_buffers;
	if (*num_planes)
		return sizes[0] < size ? -EINVAL : 0;
	
	*num_planes = 1;
	sizes[0] = size;  
	return 0;
}

static int tbs_buffer_prepare(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct tbsvideo_buffer *buf =
		container_of(vbuf, struct tbsvideo_buffer, vb);
	struct tbs_video *videodev = vb->vb2_queue->drv_priv;
	u32 size;

	size = 2* videodev->width * videodev->height; // 16bit
	if (vb2_plane_size(vb, 0) < size)
		return -EINVAL;
	vb2_set_plane_payload(vb, 0, size);
	buf->mem = vb2_plane_vaddr(vb,0);
	return 0;	
}

static void tbs_buffer_finish(struct vb2_buffer *vb)
{
	return;
}

static void tbs_buffer_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct tbs_video *videodev = vb->vb2_queue->drv_priv;
	struct tbsvideo_buffer *buf =
		container_of(vbuf, struct tbsvideo_buffer, vb);
	unsigned long flags;
	
	spin_lock_irqsave(&videodev->slock, flags);	
	list_add_tail(&buf->queue, &videodev->queue);
	spin_unlock_irqrestore(&videodev->slock, flags);
}

static void start_video_dma_transfer(struct tbs_video *videodev)
{
	struct tbs_pcie_dev *dev =videodev->dev;
	//start dma
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(videodev->index), 0x00000001); 
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_START, 0x00000001);

	TBS_PCIE_READ(TBS_DMA_BASE(videodev->index), TBS_DMA_STATUS);

	// write picture size
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_CELL_SIZE, DMA_VIDEO_CELL); 

	//write dma size
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_SIZE,DMA_VIDEO_CELL ); 

	//set dma address:
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW, videodev->dmabuf[0].dma);

	//dma Rd done
	TBS_PCIE_READ(TBS_DMA_BASE(videodev->index), TBS_DMA_SIZE);

	//set dma address:
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW, videodev->dmabuf[0].dma);

}

static void next_video_dma_transfer(struct tbs_video *videodev,unsigned char flag)
{
	struct tbs_pcie_dev *dev =videodev->dev;
	//write dma size
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_SIZE,DMA_VIDEO_CELL ); 

	//set dma address:
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_HIGH, 0);
	if(videodev->Interlaced){
		if(flag)
			TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW, videodev->dmabuf[(videodev->seqnr+1)&1].dma+DMA_VIDEO_CELL);	
		else
			TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW, videodev->dmabuf[(videodev->seqnr+1)&1].dma);	

	}else{
		TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW, videodev->dmabuf[(videodev->seqnr+1)&1].dma);	
	}
}

static void stop_video_dma_transfer(struct tbs_video *videodev)
{
	struct tbs_pcie_dev *dev =videodev->dev;
	TBS_PCIE_READ(TBS_DMA_BASE(videodev->index), TBS_DMA_STATUS);	
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(videodev->index), 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_START, 0x00000000);	
}

static int tbs_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct tbs_video *videodev = q->drv_priv;
	start_video_dma_transfer(videodev);
	videodev->seqnr = 0;	
	return 0;
}

static void tbs_stop_streaming(struct vb2_queue *q)
{
	struct tbs_video *videodev = q->drv_priv;
	unsigned long flags;
	int offset,regval;
	int index = videodev->index>>1;
	struct tbs_pcie_dev *dev = videodev->dev;

	if(index)
		offset = 32;//video1 read address
	else
		offset = 8;//video0 read and write address

	//disable PtoI: bit24 set to default value 0
	regval =0x0;
	TBS_PCIE_WRITE(0x0, offset, regval);

	if(videodev->seqnr){
		//vb2_wait_for_all_buffers(q);		
		mdelay(100);
		//printk( "%s() vb2_wait_for_all_buffers\n", __func__);
	}
	stop_video_dma_transfer(videodev);		

	spin_lock_irqsave(&videodev->slock, flags);	
	while (!list_empty(&videodev->queue)) {
		struct tbsvideo_buffer *buf = list_entry(videodev->queue.next,
			struct tbsvideo_buffer, queue);
		list_del(&buf->queue);
		vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
	}
	spin_unlock_irqrestore(&videodev->slock, flags);

}

static const struct vb2_ops tbspcie_video_qops = {
	.queue_setup    = tbs_queue_setup,
	.buf_prepare  = tbs_buffer_prepare,
	.buf_finish = tbs_buffer_finish,
	.buf_queue    = tbs_buffer_queue,
	.wait_prepare = vb2_ops_wait_prepare,
	.wait_finish = vb2_ops_wait_finish,
	.start_streaming = tbs_start_streaming,
	.stop_streaming = tbs_stop_streaming,
};

static int tbs_i2c_xfer(struct i2c_adapter *adapter,struct i2c_msg msg[], int num)
{
	struct tbs_i2c *i2c = i2c_get_adapdata(adapter);
	struct tbs_pcie_dev *dev = i2c->dev;
	u8 tmpbuf[8];

	u32 data0 = 0;
	int timeout;
	int i =0;

	if (num == 2 &&
		 msg[1].flags & I2C_M_RD && !(msg[0].flags & I2C_M_RD)) {
	//test
	tmpbuf[0] =0x81;
	tmpbuf[1] = msg[0].addr;
	tmpbuf[1] &=0xfe;
	tmpbuf[2] = msg[0].buf[0];
	if (TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL) == 1);
		i2c->ready = 0;
	
	TBS_PCIE_WRITE(i2c->base, TBS_I2C_CTRL, *(u32 *)&tmpbuf[0]);
	timeout = wait_event_timeout(i2c->wq, i2c->ready == 1, HZ);
	if (timeout <= 0) {
		printk(KERN_ERR "TBS PCIE I2C%d timeout\n", i2c->i2c_dev);
		return -EIO;
	}
	
	tmpbuf[0] =0x80;
	tmpbuf[1] = msg[0].addr;
	tmpbuf[1] &=0xfe;
	tmpbuf[1] +=1; // read operation;
	if (msg[1].len <= 4) {
		
		tmpbuf[0] |= 0x40;
	} else {
		printk(KERN_ERR "TBS PCIE I2C%d read limit is 4 bytes\n",
			i2c->i2c_dev);
		return -EIO;
	}
	tmpbuf[0] += msg[1].len;
	if (TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL) == 1);
		i2c->ready = 0;
	
	TBS_PCIE_WRITE(i2c->base, TBS_I2C_CTRL, *(u32 *)&tmpbuf[0]);
	// timeout of 1 sec 
	timeout = wait_event_timeout(i2c->wq, i2c->ready == 1, HZ);
	if (timeout <= 0) {
		printk(KERN_ERR "TBS PCIE I2C%d timeout\n", i2c->i2c_dev);
		return -EIO;}
	data0 = TBS_PCIE_READ(i2c->base, TBS_I2C_DATA);
	memcpy(msg[1].buf, &data0, msg[1].len);
	return num;

	}

	if (num == 1 && !(msg[0].flags & I2C_M_RD)) {

	tmpbuf[0] =0x80 + msg[0].len;
	tmpbuf[1] = msg[0].addr;
	tmpbuf[1] &=0xfe;
	tmpbuf[0] |= 0x40; // add stop
	for(i =0;i<msg[0].len;i++)
		tmpbuf[2+i] = msg[0].buf[i];

	if (TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL) == 1);
		i2c->ready = 0;
	
	TBS_PCIE_WRITE(i2c->base, TBS_I2C_CTRL, *(u32 *)&tmpbuf[0]);
	
	// timeout of 1 sec 
	timeout = wait_event_timeout(i2c->wq, i2c->ready == 1, HZ);
	if (timeout <= 0) {
		printk(KERN_ERR "TBS PCIE I2C%d timeout\n", i2c->i2c_dev);
		return -EIO;
	}

	return num;
	}

	if (num == 1 && (msg[0].flags & I2C_M_RD)) {	
		printk(KERN_INFO "TBS PCIE I2C%d not implemented\n", i2c->i2c_dev);
		return num;
	}	

	return -EIO;
}

static u32 tbs_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_SMBUS_EMUL;
}

struct i2c_algorithm tbs_i2c_algo = {
	.master_xfer   = tbs_i2c_xfer,
	.functionality = tbs_i2c_func,
};

static int tbs_i2c_init(struct tbs_pcie_dev *dev)
{
	struct tbs_i2c *i2c;
	struct i2c_adapter *adap;
	int i, j, err = 0;

	dev->i2c_bus[0].base = TBS_I2C_BASE_0;
	dev->i2c_bus[1].base = TBS_I2C_BASE_1;
	dev->i2c_bus[2].base = TBS_I2C_BASE_2;
	dev->i2c_bus[3].base = TBS_I2C_BASE_3;

	/* enable i2c interrupts */
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_0, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_1, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_2, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_3, 0x00000001);

	for (i = 0; i < 2; i++) {
		i2c = &dev->i2c_bus[i];
		i2c->dev = dev;
		i2c->i2c_dev = i;
		i2c->base = dev->i2c_bus[i].base;

		init_waitqueue_head(&i2c->wq);

		adap = &i2c->i2c_adap;
		i2c_set_adapdata(adap, i2c);

		/* TODO: replace X by I2C adapter number */
		strlcpy(adap->name, "TBS PCIE I2C Adapter X", sizeof(adap->name));

		adap->algo = &tbs_i2c_algo;
		adap->algo_data = dev;
		adap->dev.parent = &dev->pdev->dev;

		err = i2c_add_adapter(adap);
		if (err)
			goto fail;
	}

	return 0;

fail:
	for (j = 0; j < i; j++) {
		i2c = &dev->i2c_bus[j];
		adap = &i2c->i2c_adap;
		i2c_del_adapter(adap);
	}
	return err;
}

static void tbs_i2c_exit(struct tbs_pcie_dev *dev)
{
	struct tbs_i2c *i2c;
	struct i2c_adapter *adap;
	int i;

	for (i = 0; i < 4; i++) {
		i2c = &dev->i2c_bus[i];
		adap = &i2c->i2c_adap;
		i2c_del_adapter(adap);
	}
}


void video_data_process(struct work_struct *p_work)
{
	struct tbs_video *videodev = container_of(p_work, struct tbs_video, videowork);
	struct tbsvideo_buffer *buf;
	unsigned long flags;
	struct tbs_pcie_dev *dev = videodev->dev;
	int ret  =  TBS_PCIE_READ(TBS_DMA_BASE(videodev->index), 0);

	spin_lock_irqsave(&videodev->slock, flags);
	if(list_empty(&videodev->queue)){
		spin_unlock_irqrestore(&videodev->slock, flags);	
		return;
	}
	buf = list_entry(videodev->queue.next, struct tbsvideo_buffer, queue);
	list_del(&buf->queue);	
	buf->vb.vb2_buf.timestamp = ktime_get_ns();
	buf->vb.field = videodev->pixfmt;
	if(videodev->Interlaced){
		int i;
		for(i=0;i<videodev->height;i+=2){
			memcpy(buf->mem+(i+1)*videodev->width*2,
				(u8*)videodev->dmabuf[videodev->seqnr&1].cpu+DMA_VIDEO_CELL+(i>>1)*videodev->width*2,videodev->width*2);
			memcpy(buf->mem+(i)*videodev->width*2,
				(u8*)videodev->dmabuf[videodev->seqnr&1].cpu+(i>>1)*videodev->width*2,videodev->width*2);
		}
	buf->vb.sequence = videodev->seqnr++;
	}else{
		buf->vb.sequence = videodev->seqnr++;
		memcpy(buf->mem,(u8*)videodev->dmabuf[videodev->seqnr&1].cpu,videodev->dmabuf[videodev->seqnr&1].size);
	}
	vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_DONE);
	spin_unlock_irqrestore(&videodev->slock, flags);

	return;
}
/*
void tbs_irq_video_done(struct tbs_pcie_dev *dev, int index)
{

	struct tbsvideo_buffer *buf;
	unsigned long flags;

	spin_lock_irqsave(&dev->video[index].slock, flags);
	if(list_empty(&dev->video[index].queue)){
		spin_unlock_irqrestore(&dev->video[index].slock, flags);	
		return;
	}
	buf = list_entry(dev->video[index].queue.next, struct tbsvideo_buffer, queue);
	list_del(&buf->queue);	
	buf->vb.vb2_buf.timestamp = ktime_get_ns();
	buf->vb.field = dev->video[index].pixfmt;
	buf->vb.sequence = dev->video[index].seqnr++;
	memcpy(vb2_plane_vaddr(&buf->vb.vb2_buf,0),(u8*)dev->video[index].cpu,dev->video[index].size);
	vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_DONE);
	spin_unlock_irqrestore(&dev->video[index].slock, flags);

	next_video_dma_transfer(&dev->video[index]);
	return;
}
*/
static irqreturn_t tbs_pcie_irq(int irq, void *dev_id)
{
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev *) dev_id;
	struct tbs_i2c *i2c;
	u32 stat;
	u32 ret;
	unsigned char index;

	stat = TBS_PCIE_READ(TBS_INT_BASE, TBS_INT_STATUS);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_STATUS, stat);

	if (!(stat & 0x000000ff))
	{
		TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001); 
		return IRQ_HANDLED;
	}

	if (stat & 0x00000010){ //audio 0
		ret = TBS_PCIE_READ(TBS_DMA_BASE_0, 0);
		index = (ret)&3;
		dev->audio[0].pos = index *TBS_AUDIO_CELL_SIZE;
		snd_pcm_period_elapsed(dev->audio[0].substream);
	}

	if (stat & 0x00000020){//video 0
		ret = TBS_PCIE_READ(TBS_DMA_BASE_1, 0);
//printk("video 0 ret: %8x\n",ret);
		if(dev->video[0].Interlaced){
		//	if(ret == 0x1010100){
			if((ret & 0x1000000)==0x1000000){
				next_video_dma_transfer(&dev->video[0],0);
				queue_work(wq,&dev->video[0].videowork);
			}else{
				next_video_dma_transfer(&dev->video[0],1);
			}

		}else{
			next_video_dma_transfer(&dev->video[0],1);
			queue_work(wq,&dev->video[0].videowork);
		}
	}
	if (stat & 0x00000040){ //audio 1
		ret = TBS_PCIE_READ(TBS_DMA_BASE_2, 0);
		index = (ret)&3;
		dev->audio[1].pos = index *TBS_AUDIO_CELL_SIZE;
		snd_pcm_period_elapsed(dev->audio[1].substream);
	}

	if (stat & 0x00000080){//video 1
		ret = TBS_PCIE_READ(TBS_DMA_BASE_3, 0);
//printk("video 1 ret: %8x\n",ret);
		if(dev->video[1].Interlaced){
		//	if(ret == 0x1010100){
			if((ret & 0x1000000)==0x1000000){
				next_video_dma_transfer(&dev->video[1],0);
				queue_work(wq,&dev->video[1].videowork);
			}else{
				next_video_dma_transfer(&dev->video[1],1);
			}
		}else{
			next_video_dma_transfer(&dev->video[1],1);
			queue_work(wq,&dev->video[1].videowork);
		}
	}
	
	if (stat & 0x00000001) {
		i2c = &dev->i2c_bus[0];
		i2c->ready = 1;
		wake_up(&i2c->wq);	
	}
	if (stat & 0x00000002) {
		i2c = &dev->i2c_bus[1];
		i2c->ready = 1;
		wake_up(&i2c->wq);
	}
	if (stat & 0x00000004) {
		i2c = &dev->i2c_bus[2];
		i2c->ready = 1;
		wake_up(&i2c->wq);
	}
	if (stat & 0x00000008) {
		i2c = &dev->i2c_bus[3];
		i2c->ready = 1;
		wake_up(&i2c->wq);
	}

	/* enable interrupt */
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);
	return IRQ_HANDLED;
}
static void signaltable(u32 val, u32 *wid, u32 *high,u32 *freq, u32 *interlaced )
{
	switch(val)
	{
		case 0x16:
		case 0x17:
		case 0x1B:
		case 0x19:
			// 720(1440)*480i @ 59.94/60hz
			*wid = 720;
			*high = 480;
			*freq = 60;
			*interlaced = 1;
		break;
		case 0x18:
		case 0x1A:
			// 720(1440)*576i @ 50hz 
			*wid = 720;
			*high = 576;///2;
			*freq = 50;
			*interlaced = 1;
		break;
		case 0x20:
		case 0x00:
			// 1280*720p @ 59.94/60hz
			*wid = 1280;
			*high = 720;
			*freq = 60;
			*interlaced = 0;
		break;
		case 0x24:
		case 0x04:
			// 1280*720p @ 50hz
			*wid = 1280;
			*high = 720;
			*freq = 50;
			*interlaced = 0;
		break;
		case 0x2a:
		case 0x0a:
			// 1920*1080i @ 59.94/60hz
			*wid = 1920;
			*high = 1080;
			*freq = 60;
			*interlaced = 1;
		break;
		case 0x2c:
		case 0x0c:
			// 1920*1080i @ 50hz 
			*wid = 1920;
			*high = 1080;
			*freq = 50;
			*interlaced = 1;
		break;
		case 0x0b:
			// 1920*1080p @ 29.97/30hz
			*wid = 1920;
			*high = 1080;
			*freq = 30;
			*interlaced = 0;
		break;

		case 0x0d:
			// 1920*1080p @ 25hz
			*wid = 1920;
			*high = 1080;
			*freq = 25;
			*interlaced = 0; 
		break;

		case 0x30:
		case 0x10:
			// 1920*1080p @ 23.98/24hz
			*wid = 1920;
			*high = 1080;
			*freq = 24;
			*interlaced = 0;
		break;
		case 0x2b:
			// 1920*1080p @ 59.94/60hz
			*wid = 1920;
			*high = 1080;
			*freq = 60;
			*interlaced = 0;
		break;
		case 0x2d:
			// 1280*720p @ 50hz
			*wid = 1920;
			*high = 1080;
			*freq = 50;
			*interlaced = 0;
		break;

		/////// add /////////////////
		case 0x02:
			// 1280*720p @ 30
			*wid = 1280;
			*high = 720;
			*freq = 30;
			*interlaced = 0;
		break;
		case 0x03:
			// 1280*720p @ 30 -EM
			*wid = 1280;
			*high = 720;
			*freq = 30;
			*interlaced = 0;
		break;
		case 0x05:
			// 1280*720p @ 50 -EM
			*wid = 1280;
			*high = 720;
			*freq = 50;
			*interlaced = 0;
		break;
		case 0x06:
			// 1280*720p @ 25
			*wid = 1280;
			*high = 720;
			*freq = 25;
			*interlaced = 0;
		break;
		case 0x07:
			// 1280*720p @ 25 -EM
			*wid = 1280;
			*high = 720;
			*freq = 25;
			*interlaced = 0;
		break;
		case 0x08:
			// 1280*720p @ 24
			*wid = 1280;
			*high = 720;
			*freq = 24;
			*interlaced = 0;
		break;
		case 0x09:
			// 1280*720p @ 24 -EM
			*wid = 1280;
			*high = 720;
			*freq = 24;
			*interlaced = 0;
		break;
		case 0x12:
			// 1920*1080p @ 24 -
			*wid = 1920;
			*high = 1080;
			*freq = 24;
			*interlaced = 0;
		break;
		case 0x14:
			// 1920*1080i @ 50
			*wid = 1920;
			*high = 1080;
			*freq = 50;
			*interlaced = 1;
		break;
		case 0x15:
			// 1920*1035i @ 60
			*wid = 1920;
			*high = 1035;
			*freq = 60;
			*interlaced = 1;
		break;
		case 0x26:
			// 1280*720p @ 25
			*wid = 1280;
			*high = 720;
			*freq = 25;
			*interlaced = 0;
		break;
		case 0x28:
			// 1280*720p @ 24
			*wid = 1280;
			*high = 720;
			*freq = 24;
			*interlaced = 0;
		break;
		default:
			// 1920*1080p @ 25hz
			*wid = 1920;
			*high = 1080;
			*freq = 25;
			*interlaced = 0;
		break;
	}
	return;

}
static void tbs_sdi_video_param(struct tbs_pcie_dev *dev,int index)
{
	u32 v_regdata;
	u32 v_width,v_height, v_interlaced,v_refq=0;
	int regval;
	int ptoi = 0;
	int itoi = 0;

	v_regdata = sdi_read16bit(dev,ASI0_BASEADDRESS,0x06);
	v_regdata = (v_regdata & 0x3f00)>>8;
	//printk("SDI signal reg value : %x\n", v_regdata);

	if(v_regdata==0x1d)
	{
		printk("SDI cable is not connect! \n");

		dev->video[index].width = 1280;		
		dev->video[index].height = 720;
		return;
	}

	signaltable(v_regdata,&v_width,&v_height,&v_refq,&v_interlaced);
	dev->video[index].width = v_width;
	dev->video[index].height = v_height;
	dev->video[index].fps = v_refq;

	if(!v_interlaced && v_refq>30 && dev->video[index].width==1920 && dev->video[index].height==1080) 		
	{
		printk("SDI 1080 50/60 Progressive change to Interlaced Input  \n");
		dev->video[index].Interlaced = 1;
		dev->video[index].fps>>=1;
		//enable PtoI: bit24 set to 1 by gpio offset address 8
		regval =0x1;
		TBS_PCIE_WRITE(0x0, 8, regval);

	}
	else{
		//disable PtoI: bit24 set to default value 0
		regval =0x0;
		TBS_PCIE_WRITE(0x0, 8, regval);
		dev->video[index].Interlaced = v_interlaced;
		if(v_interlaced)
		{
			dev->video[index].fps>>=1;
			printk("SDI Interlaced Input  \n");
		}
		else
			printk("SDI Progressive Input  \n");
	}
	printk("pix:%d line:%d frameRate:%d IorP:%d regvalue:%x\n",dev->video[index].width,dev->video[index].height,v_refq,dev->video[index].Interlaced,v_regdata );	

}
static void tbs_hdmi_video_param(struct tbs_pcie_dev *dev,int index)
{
	struct tbs_adapter *tbs_adap;
	struct pci_dev *pci = dev->pdev;
	u8 tmp[2];
	u32 tmp_B,v_refq=0;
	int regval;
	int offset;
	int ptoi = 0;
	int itoi = 0;

	tbs_adap = &dev->tbs_pcie_adap[index];

	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x98, 0x6f,tmp,1);
	if((tmp[0]&0x01)==0)
	{
		printk("HDMI cable is not connect! \n");

		dev->video[index].width = 1280;		
		dev->video[index].height = 720;
		return;
	}
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x68, 0x07,tmp, 2);
	dev->video[index].width = (tmp[0]&0x1f)*256+tmp[1];		
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x68, 0x09,tmp, 2);
	dev->video[index].height =(tmp[0]&0x1f)*256+tmp[1];	

	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x44,0xb8,tmp,2);
	tmp_B=((tmp[0]&0x1f)<<8)+tmp[1];
	if(tmp_B)
		v_refq = (unsigned char) ((103663 + (tmp_B -1)) / tmp_B);	
	dev->video[index].fps=v_refq;

	if(index)
		offset = 20;//video1 read address
	else
		offset = 8;//video0 read and write address
	ptoi  = TBS_PCIE_READ(0x0, offset);
	
	if(index)
		offset = 32;//video1 write address
	else
		offset = 8;

	if(v_refq>30 && dev->video[index].width==1920 && dev->video[index].height==1080) 		
	{
		printk("HDMI 1080 50/60 Progressive change to Interlaced Input  \n");
		dev->video[index].Interlaced = 1;
		dev->video[index].fps>>=1;
		//enable PtoI: bit24 set to 1 by gpio offset address 8
		regval =0x1;
		TBS_PCIE_WRITE(0x0, offset, regval);

	}
	else if((v_refq>50) && (dev->video[index].width==1280) && (dev->video[index].height==720) &&(pci->subsystem_vendor ==0x6312)) 		
	{
		printk("HDMI 720 60 Progressive change to Interlaced Input  \n");
		dev->video[index].Interlaced = 1;
		dev->video[index].fps>>=1;
		//enable PtoI: bit24 set to 1 by gpio offset address 8
		regval =0x1;
		TBS_PCIE_WRITE(0x0, offset, regval);

	}
	else{
		//disable PtoI: bit24 set to default value 0
		//regval =0x0;
		//TBS_PCIE_WRITE(0x0, offset, regval);

		i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x68,0x0b,tmp,1);
		if (tmp[0]&0x20){
			printk("HDMI Interlaced Input  \n");
			dev->video[index].Interlaced = 1;
			dev->video[index].height<<=1;
			dev->video[index].fps>>=1;
			//disable PtoI: bit24 set to default value 0
			regval =0x0;
			TBS_PCIE_WRITE(0x0, offset, regval);
		}
		else if(ptoi ==1) // deal to ptoi 
		{
			printk("HDMI Progressive change to Interlaced Input  \n");
			dev->video[index].Interlaced = 1;
			dev->video[index].fps>>=1;
		}
		else{
			printk("HDMI Progressive Input  \n");
			dev->video[index].Interlaced = 0;
		}
	}
	printk("pix:%d line:%d frameRate:%d\n",dev->video[index].width,dev->video[index].height,v_refq);	

}
static void tbs6314_mac(struct tbs_adapter *tbs_adap)
{
	struct tbs_pcie_dev *dev = tbs_adap->dev;
	u8 tmp[8];

	//read mac address:
	tbs_adap = &dev->tbs_pcie_adap[0];
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0xa0, 0xa0,tmp, 4);
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0xa0, 0xa4,tmp+4, 2);
	//printk("mac address : %x, %x, %x, %x, %x, %x\n", tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]);

}
static void tbs6312_mac(struct tbs_adapter *tbs_adap)
{
	struct tbs_pcie_dev *dev = tbs_adap->dev;
	u8 tmp[8];

	//read mac address:
	tbs_adap = &dev->tbs_pcie_adap[1];
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0xa0, 0xa0,tmp, 4);
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0xa0, 0xa4,tmp+4, 2);
	printk("mac address : %x, %x, %x, %x, %x, %x\n", tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]);
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0xa0, 0xb0,tmp, 4);
	i2c_read_reg(&tbs_adap->i2c->i2c_adap,0xa0, 0xb4,tmp+4, 2);
	printk("mac address : %x, %x, %x, %x, %x, %x\n", tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5]);	

}
static void tbs_adapters_init(struct tbs_pcie_dev *dev)
{
	struct tbs_adapter *tbs_adap;
	struct pci_dev *pci = dev->pdev;
	int i;
	u8 tmp[8];

	/* disable all interrupts */
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001); 

	/* disable dma */
	TBS_PCIE_WRITE(TBS_DMA_BASE_0, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_1, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_2, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_3, TBS_DMA_START, 0x00000000);
	switch(pci->subsystem_vendor){
	case 0x6312:
		printk("tbs6312 card\n");
		dev->nr = 2;
		break;
	case 0x6314:
		printk("tbs6314 card\n");
		dev->nr = 1;
		break;
	case 0x6324:
		printk("tbs6324 card\n");
		dev->nr = 1;
		break;
	default:
		printk("unknonw card\n");
	}

	for (i = 0; i <dev->nr; i++) {
	tbs_adap = &dev->tbs_pcie_adap[i];
	tbs_adap->dev = dev;
	tbs_adap->count = i;
	tbs_adap->i2c = &dev->i2c_bus[i];
	if(pci->subsystem_vendor == 0x6324) //tbs6324 sdi
	{
		// init asi
		int regdata;
		u8 mpbuf[4];
		mpbuf[0] = 0; //0--3 select value
		TBS_PCIE_WRITE( TBS_GPIO_BASE, 0x34 , *(u32 *)&mpbuf[0]); // select chip : 13*8 =104=0x68 select address

		sdi_chip_reset(dev,ASI0_BASEADDRESS);  //asi chip reset;

		mpbuf[0] = 1; //active spi bus from "z"
		TBS_PCIE_WRITE( ASI0_BASEADDRESS, ASI_SPI_ENABLE, *(u32 *)&mpbuf[0]);
		regdata = sdi_read16bit(dev,ASI0_BASEADDRESS,0x24);
		printk("GS2971 chip id : %x\n",regdata);
		tbs_sdi_video_param(dev,i);
		
	}
	else
	{
		//read 7611 id and init chip here
		i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x98, 0xea,tmp, 2);
		printk("7611 chip id : %x, %x\n", tmp[0],tmp[1]);

		//reset
		tmp[0] = 0xff;
		tmp[1] = 0x80;
		i2c_write_reg(&tbs_adap->i2c->i2c_adap,0x98, tmp,2);
		mdelay(200);//sleep

		i2c_write_tab_new(&tbs_adap->i2c->i2c_adap, fw7611);
		mdelay(200);
		tbs_hdmi_video_param(dev,i);
	}
	
	}

	switch(pci->subsystem_vendor){
	case 0x6312:
		tbs6312_mac(tbs_adap);
		break;
	case 0x6314:
		tbs6314_mac(tbs_adap);
		break;
	}

}

int tbs_video_register(struct tbs_pcie_dev *dev)
{
	struct video_device *vdev ;
	struct vb2_queue *q ;
	int i;
	int err=-1;
	for(i=0;i<dev->nr;i++){
		err = v4l2_device_register(&dev->pdev->dev, &dev->video[i].v4l2_dev);
		if(err<0){
			printk(KERN_ERR " v4l2_device_register %d error! \n",i);
			return -1;
		}

	}
	
	for(i=0;i<dev->nr;i++){
		vdev = &(dev->video[i].vdev);
		q = &(dev->video[i].vq);
		if (NULL == vdev){
			printk(KERN_ERR " video_device_alloc failed ! \n");
			goto fail;
		}
		dev->video[i].index = i*2+1;
		dev->video[i].dev = dev;	
		dev->video[i].std = V4L2_STD_NTSC_M;
		dev->video[i].pixfmt = V4L2_PIX_FMT_UYVY;
		vdev->v4l2_dev = &(dev->video[i].v4l2_dev);
		vdev->lock = &(dev->video[i].video_lock);
		vdev->fops = &tbs_fops;
		strcpy(vdev->name,KBUILD_MODNAME);
		vdev->release = video_device_release_empty;
		video_set_drvdata(vdev, &(dev->video[i]));

		vdev->ioctl_ops = &tbs_ioctl_fops;
		mutex_init(&(dev->video[i].video_lock));
		mutex_init(&(dev->video[i].queue_lock));
		spin_lock_init(&dev->video[i].slock);

		INIT_LIST_HEAD(&dev->video[i].queue);
		q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		q->io_modes = VB2_MMAP | VB2_USERPTR | VB2_DMABUF | VB2_READ;

		q->gfp_flags = GFP_DMA32;
		q->min_buffers_needed = 2;
		q->drv_priv = &(dev->video[i]);
		q->buf_struct_size = sizeof(struct tbsvideo_buffer);
		q->ops = &tbspcie_video_qops;
		q->mem_ops = &vb2_dma_sg_memops;
		q->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
		q->lock = &(dev->video[i].queue_lock);
		q->dev = &(dev->pdev->dev);
		vdev->queue = q;	
		err = vb2_queue_init(q);
		if(err != 0){
			printk(KERN_ERR " vb2_queue_init failed! \n");
			goto fail;	
		}

		INIT_WORK(&dev->video[i].videowork,video_data_process);
		
		dev->video[i].dmabuf[0].cpu = dma_alloc_coherent(&dev->pdev->dev,  4095*1024, &dev->video[i].dmabuf[0].dma, GFP_KERNEL);
		if (!dev->video[i].dmabuf[0].cpu) {
			printk(" allocate memory failed\n");
			goto fail;
		}
		dev->video[i].dmabuf[1].cpu = dma_alloc_coherent(&dev->pdev->dev,  4095*1024, &dev->video[i].dmabuf[1].dma, GFP_KERNEL);
		if (!dev->video[i].dmabuf[1].cpu) {
			printk(" allocate memory failed\n");
			goto fail;
		}

		err = video_register_device(vdev, VFL_TYPE_VIDEO,-1);
		if(err!=0){
			printk(KERN_ERR " v4l2_device_register failed!\n");
			goto fail;
		}else{
			printk(" TBS video Capture %d register OK! \n",i);
		}
	}
	return 0;
fail:
	for(i=0;i<dev->nr;i++){
		if(!dev->video[i].dmabuf[0].cpu){
				dma_free_coherent(&dev->pdev->dev,  4095*1024, dev->video[i].dmabuf[0].cpu, dev->video[i].dmabuf[0].dma);
				dev->video[i].dmabuf[0].cpu =NULL;
		}
		if(!dev->video[i].dmabuf[1].cpu){
				dma_free_coherent(&dev->pdev->dev,  4095*1024, dev->video[i].dmabuf[1].cpu, dev->video[i].dmabuf[1].dma);
				dev->video[i].dmabuf[1].cpu =NULL;
		}
		vdev = &dev->video[i].vdev;
		video_unregister_device(vdev);
		v4l2_device_unregister(&dev->video[i].v4l2_dev);
	}
	return err;
}

/* HDMI 0x39[3:0] - CS_DATA[27:24] 0 for reserved values*/
static const int cs_data_fs[] = {
	44100,
	0,
	48000,
	32000,
	0,
	0,
	0,
	0,
	88200,
	768000,
	96000,
	0,
	176000,
	0,
	192000,
	0,
};

static struct snd_pcm_hardware mycard_capture_stero ={
	.info =  (SNDRV_PCM_INFO_INTERLEAVED |SNDRV_PCM_INFO_BLOCK_TRANSFER ),
	.formats = (SNDRV_PCM_FMTBIT_S16_LE),
	.rates = SNDRV_PCM_RATE_KNOT | SNDRV_PCM_RATE_8000_192000,
	.rate_min = 8000,
	.rate_max = 192000,
	.channels_min = 2,
	.channels_max =2,
	.period_bytes_min = TBS_AUDIO_CELL_SIZE,
	.period_bytes_max = TBS_AUDIO_CELL_SIZE,
	.periods_min      = 4,
	.periods_max      = 4,
	.buffer_bytes_max = TBS_AUDIO_CELL_SIZE*4,
};

int tbs_pcie_audio_open(struct snd_pcm_substream *substream)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct tbs_adapter *tbs_adap;
	unsigned int rate,setrate=44100;
	struct pci_dev *pci = chip->dev->pdev;

	u8 tmp[2];
	chip->substream = substream;
	runtime->hw = mycard_capture_stero;
	
	if(pci->subsystem_vendor == 0x6324) //tbs6324 sdi
	{
		setrate=48000;//sdi
		//printk(KERN_INFO " tbs6324 sdi audio set to 48000\n");
	}
	else
	{
		tbs_adap = &chip->dev->tbs_pcie_adap[chip->index>>1];
		i2c_read_reg(&tbs_adap->i2c->i2c_adap,0x68, 0x39,tmp, 1);	
		rate = cs_data_fs[tmp[0]&15];
		if(rate)
			setrate = rate;
	}
	
	//printk(KERN_INFO "%s() index:%x rate:%d setrate:%d tmp[0]:%d\n",__func__, chip->index,rate,setrate,tmp[0]&15);
	snd_pcm_hw_constraint_minmax(runtime,SNDRV_PCM_HW_PARAM_RATE,setrate,setrate);
	return 0;
}

int tbs_pcie_audio__close(struct snd_pcm_substream *substream)
{
//	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	return 0;
} 
int tbs_pcie_audio_hw_params(struct snd_pcm_substream *substream, struct snd_pcm_hw_params *hw_params)
{
	return snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hw_params));
}  

int tbs_pcie_audio_hw_free(struct snd_pcm_substream *substream)
{
	return snd_pcm_lib_free_pages(substream);
} 

int tbs_pcie_audio_prepare(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct tbs_pcie_dev *dev= chip->dev;
	int i;

	for(i=0;i<2;i++){
		//set dma address:
		TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_ADDR_HIGH, 0);
		TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_ADDR_LOW, runtime->dma_addr);

		//write dma size
		TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_SIZE,TBS_AUDIO_CELL_SIZE*4 ); 
		// write picture size
		TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_CELL_SIZE, TBS_AUDIO_CELL_SIZE); 

		msleep(10);
	}

	chip->pos=0;

	return 0;
}  
int tbs_pcie_audio_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct tbs_pcie_dev *dev= chip->dev;
	switch(cmd){
		case SNDRV_PCM_TRIGGER_START:
			TBS_PCIE_READ(TBS_DMA_BASE(chip->index), TBS_DMA_STATUS);
			//start dma
			TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(chip->index), 0x00000001); 
			TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_START, 0x00000001);		
			break;
		case SNDRV_PCM_TRIGGER_STOP:
			//stop dma
			TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(chip->index), 0x000000000); 
			TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_START, 0x00000000);		
			break;
		default:
			return -EINVAL;
			break;
	}
	return 0;
}  

static snd_pcm_uframes_t tbs_pcie_audio_pointer(struct snd_pcm_substream *substream)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	return bytes_to_frames(runtime,chip->pos);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
static int tbs_pcie_audio_copy_user(struct snd_pcm_substream *substream,
	int channel,
	unsigned long pos,
	void __user *dst,
	unsigned long count)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int ret;
	ret = copy_to_user(dst,runtime->dma_area+pos,count);
	return 0;
}
#else
static int tbs_pcie_audio_copy(struct snd_pcm_substream *substream,
	int channel,
	snd_pcm_uframes_t pos,
	void __user *dst,
	snd_pcm_uframes_t count)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int ret;
	ret = copy_to_user(dst,runtime->dma_area+frames_to_bytes(runtime,pos),frames_to_bytes(runtime,count));
	return 0;
}
#endif

struct snd_pcm_ops tbs_pcie_pcm_ops ={
	.open =			tbs_pcie_audio_open,
	.close = 		tbs_pcie_audio__close,
	.ioctl =		snd_pcm_lib_ioctl,
	.hw_params = 	tbs_pcie_audio_hw_params,
	.hw_free =		tbs_pcie_audio_hw_free,
	.prepare =		tbs_pcie_audio_prepare,
	.trigger =		tbs_pcie_audio_trigger,
	.pointer =		tbs_pcie_audio_pointer,
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0)
	.copy_user =	tbs_pcie_audio_copy_user,
#else
	.copy =			tbs_pcie_audio_copy,
#endif
};

int tbs_audio_register(struct tbs_pcie_dev *dev)
{
	struct snd_pcm		*pcm;
	struct snd_card 	*card;
	int ret;
	int i;
	char audioname[100];
	for(i=0;i<dev->nr;i++){
		sprintf(audioname,"tbs_pcie audio %d",i);
		ret = snd_card_new(&dev->pdev->dev, -1, audioname, THIS_MODULE,	sizeof(struct tbs_audio), &card);
		if (ret < 0){
			printk(KERN_ERR "%s() ERROR: snd_card_new failed <%d>\n",__func__, ret);
			goto fail0;
		}
		strcpy(card->driver, KBUILD_MODNAME);
		strcpy(card->shortname, "tbs_pcie audio");
		sprintf(card->longname, "%s %x",card->shortname,i);

		ret = snd_pcm_new(card,audioname,0,0,1,&pcm);
		if (ret < 0){
			printk(KERN_ERR "%s() ERROR: snd_pcm_new failed <%d>\n",__func__, ret);
			goto fail1;
		}
		dev->audio[i].index=i*2;
		dev->audio[i].dev=dev;
		pcm->private_data = &dev->audio[i];		
		snd_pcm_set_ops(pcm,SNDRV_PCM_STREAM_CAPTURE,&tbs_pcie_pcm_ops);
		snd_pcm_lib_preallocate_pages_for_all(pcm, SNDRV_DMA_TYPE_DEV,&dev->pdev->dev, TBS_AUDIO_CELL_SIZE*4, TBS_AUDIO_CELL_SIZE*4);
		ret = snd_card_register(card);
		if ( ret < 0) {
			printk(KERN_ERR "%s() ERROR: snd_card_register failed\n",__func__);
			goto fail1;
		}
		dev->audio[i].card =card;
	}
	return 0;
fail1:
	for(i=0;i<dev->nr;i++){
		if(dev->audio[i].card)
			snd_card_free(dev->audio[i].card);
		dev->audio[i].card=NULL;
	}
fail0:
	return -1;
}

static void tbs_remove(struct pci_dev *pdev)
{
	struct tbs_pcie_dev *dev = 
		(struct tbs_pcie_dev*) pci_get_drvdata(pdev);
	
	struct video_device *vdev;
	int i;

	for(i=0;i<2;i++){
		if(dev->audio[i].card)
			snd_card_free(dev->audio[i].card);
		dev->audio[i].card=NULL;
	}

	for(i=0;i<2;i++){
		if(!dev->video[i].dmabuf[0].cpu){
				dma_free_coherent(&dev->pdev->dev,  4095*1024,dev->video[i].dmabuf[0].cpu, dev->video[i].dmabuf[0].dma);
				dev->video[i].dmabuf[0].cpu =NULL;
		}
		if(!dev->video[i].dmabuf[1].cpu){
				dma_free_coherent(&dev->pdev->dev,  4095*1024,dev->video[i].dmabuf[1].cpu, dev->video[i].dmabuf[1].dma);
				dev->video[i].dmabuf[1].cpu =NULL;
		}
		vdev = &dev->video[i].vdev;
		video_unregister_device(vdev);
		v4l2_device_unregister(&dev->video[i].v4l2_dev);
	}

	tbs_i2c_exit(dev);
	/* disable interrupts */
	free_irq(dev->pdev->irq, dev);

	if (dev->mmio)
		iounmap(dev->mmio);

	kfree(dev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int tbs_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
	struct tbs_pcie_dev *dev;
	int err = 0, ret = -ENODEV;

	dev  = kzalloc(sizeof (struct tbs_pcie_dev), GFP_KERNEL);
	if (dev == NULL) {
		printk(KERN_ERR "pcie_tbs_probe ERROR: out of memory\n");
		ret = -ENOMEM;
		goto fail0;
	}

	dev->pdev = pdev;

	err = pci_enable_device(pdev);
	if (err != 0) {
		ret = -ENODEV;
		printk(KERN_ERR "pcie_tbs_probe ERROR: PCI enable failed (%i)\n", err);
		goto fail1;
	}

	dev->mmio = ioremap(pci_resource_start(dev->pdev, 0),
			pci_resource_len(dev->pdev, 0));
	if (!dev->mmio) {
		printk(KERN_ERR "pcie_tbs_probe ERROR: Mem 0 remap failed\n");
		ret = -ENODEV; /* -ENOMEM better?! */ 
		goto fail2;
	}

	ret = request_irq(dev->pdev->irq,tbs_pcie_irq,IRQF_SHARED,KBUILD_MODNAME,(void *) dev);
	if (ret < 0) {
		printk(KERN_ERR "pcie_tbs_probe ERROR: IRQ registration failed <%d>\n", ret);
		ret = -ENODEV;
		goto fail2;
	}

	pci_set_drvdata(pdev, dev);
	
	if (tbs_i2c_init(dev) < 0)
		goto fail3;

	tbs_adapters_init(dev);

	if( tbs_video_register(dev) )
		goto fail3;

	if(tbs_audio_register(dev))
		goto fail3;
			
	return 0;

fail3:
	free_irq(dev->pdev->irq, dev);
	if (dev->mmio)
		iounmap(dev->mmio);
fail2:
	pci_disable_device(pdev);
fail1:
	pci_set_drvdata(pdev, NULL);
	kfree(dev);
fail0:
	return ret;
}

#define MAKE_ENTRY( __vend, __chip, __subven, __subdev, __configptr) {	\
	.vendor		= (__vend),					\
	.device		= (__chip),					\
	.subvendor	= (__subven),					\
	.subdevice	= (__subdev),					\
	.driver_data	= (unsigned long) (__configptr)			\
}

static const struct pci_device_id tbs_pci_table[] = {
	MAKE_ENTRY(0x544d, 0x6178, 0x6312, 0x0002, NULL),
	MAKE_ENTRY(0x544d, 0x6178, 0x6312, 0x2000, NULL),
	MAKE_ENTRY(0x544d, 0x6178, 0x6314, 0x1000, NULL),
	MAKE_ENTRY(0x544d, 0x6178, 0x6324, 0x8000, NULL), // sdi
	{ }
};
MODULE_DEVICE_TABLE(pci, tbs_pci_table);

static struct pci_driver tbs_pci_driver = {
	.name        = KBUILD_MODNAME,
	.id_table    = tbs_pci_table,
	.probe       = tbs_probe,
	.remove      = tbs_remove,
};

static __init int pcie_tbs_init(void)
{
	wq = create_singlethread_workqueue("tbs");
	return pci_register_driver(&tbs_pci_driver);
}

static __exit void pcie_tbs_exit(void)
{
	if(wq)
		destroy_workqueue(wq);
	wq=NULL;
	pci_unregister_driver(&tbs_pci_driver);
}

module_init(pcie_tbs_init);
module_exit(pcie_tbs_exit);

MODULE_DESCRIPTION("TBS PCIE driver");
MODULE_AUTHOR("kernelcoding <wugang@kernelcoding.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
