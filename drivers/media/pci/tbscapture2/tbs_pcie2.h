/*
    TurboSight PCIex2 HDMI capture cards driver
     Copyright (C) 2024 www.tbsdtv.com
*/

#ifndef _TBS_PCIE2_H_
#define _TBS_PCIE2_H_

#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <asm/fpu/api.h>

#include <media/v4l2-ioctl.h>
#include <media/v4l2-event.h>
#include <media/v4l2-common.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ctrls.h>
#include <media/videobuf2-v4l2.h>
#include <media/videobuf2-vmalloc.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-dma-sg.h>
#include <sound/core.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/jack.h>
#include <sound/opl3.h>


#define TBS_PCIE_WRITE(__addr, __offst, __data)	writel((__data), (dev->mmio + (__addr + __offst)))
#define TBS_PCIE_READ(__addr, __offst)		readl((dev->mmio + (__addr + __offst)))


#define DMA_AUDIO_CELL          (1920)
#define AUDIO_CELLS             16
#define DMA_AUDIO_TOTAL         (DMA_AUDIO_CELL*AUDIO_CELLS)

#define DMA_VIDEO_TOTAL			(4096*1024)
#define FILE_INSTANCE_SIZE		(8192*1024)
#define FILE_HANDLE_POS			(0x3F5000)


#define	DEFAULT_WIDTH	176
#define	DEFAULT_HEIGH	120

#define TBS_NORMS  V4L2_STD_NTSC_M

#define DELAYMS	1


#define	UNSET	(-1U)

struct tbs_pcie_dev;

struct tbs_i2c {
	struct tbs_pcie_dev	*dev;
	u8					i2c_dev;
	struct i2c_adapter	i2c_adap;
	u32					base;
	int					ready;
	wait_queue_head_t	wq;
	struct work_struct	i2cwork;

};


/* buffer for one video frame */
struct tbsvideo_buffer {
	/* common v4l buffer stuff -- must be first */
	struct vb2_v4l2_buffer	vb;
	struct list_head		queue;
};

struct tbs_dmabuf{
	__le32					*virtaddr;
	dma_addr_t				dma;	
};

struct tbs_video{
	struct tbs_pcie_dev		*dev;
	struct v4l2_device		v4l2_dev;
	struct video_device		vdev;

	int						index;
	int						width,height;
	int						Interlaced;
	int						fps;
	v4l2_std_id				std;  //V4L2_STD_NTSC_M

	int						dst_width,dst_height;

//	int						select_width,select_height;
//	unsigned				select_pixelformat;
	int						img_ready;
	wait_queue_head_t		wq;
	struct work_struct		videowork;

	unsigned				runstatus;

	unsigned 				videostatus;

	struct mutex			video_lock;

	struct	tbs_dmabuf		dmabuf[3];
	unsigned				present;
};
	
struct tbs_audio{
	struct tbs_pcie_dev		*dev;
	struct snd_card 		*card;	
	struct snd_pcm			*pcm;
	struct snd_pcm_substream *substream;
	int						pos;
	int						index;
	struct work_struct		audiowork;
	unsigned				runstatus;
};
	

struct tbs_pcie_dev {
	struct pci_dev			*pdev;
	void __iomem			*mmio;	
	struct tbs_audio		audio[INTERFACES];
	struct tbs_video		video[INTERFACES];
	struct tbs_i2c			i2c_bus[INTERFACES];
	struct mutex			devicemutex;
	struct task_struct *	signalthread;
	int						signal_ready;
	wait_queue_head_t		wq;
	bool			msi;
};


struct tbs_videofile_instance {
	struct vb2_queue		queue;
	struct mutex			queue_lock;
	struct task_struct *	stream_thread;
	struct list_head		list;
	spinlock_t				slock;
	struct v4l2_fh			fh;
	int						select_width,select_height;
	unsigned				select_pixelformat;
	unsigned				seqnr;
	unsigned char	*		imgbuf0;
	unsigned char	*		imgbuf1;
};

#endif
