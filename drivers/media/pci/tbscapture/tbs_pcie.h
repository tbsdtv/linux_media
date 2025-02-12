/*
    TurboSight TBS PCIE HDMI/SDI capture driver
     Copyright (C) 2017 www.tbsdtv.com
*/

#ifndef _TBS_PCIE_H_
#define _TBS_PCIE_H_

#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/delay.h>

#include <media/v4l2-ioctl.h>
#include <media/v4l2-event.h>
#include <media/v4l2-common.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ctrls.h>
#include <media/videobuf2-v4l2.h>
#include <media/videobuf2-dma-sg.h>

#include <sound/core.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/opl3.h>


#define TBS_PCIE_WRITE(__addr, __offst, __data)	writel((__data), (dev->mmio + (__addr + __offst)))
#define TBS_PCIE_READ(__addr, __offst)		readl((dev->mmio + (__addr + __offst)))


#define	UNSET	(-1U)

struct tbs_pcie_dev;
struct tbs_adapter;

struct tbs_i2c {
	struct tbs_pcie_dev	*dev;
	u8					i2c_dev;
	struct i2c_adapter	i2c_adap;
	u32					base;
	int					ready;
	wait_queue_head_t	wq;
};

struct tbs_adapter {
	struct tbs_pcie_dev		*dev;
	struct tbs_i2c			*i2c;
	u32						buffer;
	int						count;	
};

/* buffer for one video frame */
struct tbsvideo_buffer {
	/* common v4l buffer stuff -- must be first */
	struct vb2_v4l2_buffer	vb;
	struct list_head		queue;
	void *					mem;

};

struct tbs_dmabuf{
	unsigned int			size;
	__le32					*cpu;
	dma_addr_t				dma;	
};

struct tbs_video{
	struct tbs_pcie_dev		*dev;
	struct v4l2_device		v4l2_dev;
	struct video_device		vdev;
	struct vb2_queue		vq;
	struct list_head		queue;
	int						width,height;
	unsigned				seqnr;
	struct mutex			video_lock;
	struct mutex			queue_lock;
	spinlock_t				slock;
	v4l2_std_id				std;  //V4L2_STD_NTSC_M
	u32						pixfmt; //V4L2_PIX_FMT_YUYV(fourcc)
	int						index;
	struct work_struct		videowork;
	int						Interlaced;
	struct	tbs_dmabuf		dmabuf[2];
	u32				fps;
};
	
struct tbs_audio{
	struct tbs_pcie_dev		*dev;
	struct snd_card 		*card;	
	struct snd_pcm_substream *substream;
	int						pos;
	int						index;
};
	

struct tbs_pcie_dev {
	struct pci_dev			*pdev;
	void __iomem			*mmio;
	int 				nr;
	
	struct tbs_audio		audio[2];
	struct tbs_video		video[2];
	
	struct tbs_adapter		tbs_pcie_adap[4];
	struct tbs_i2c			i2c_bus[4];

	struct work_struct		video_work;
	struct work_struct		audio_work;
	
};

/* tbsecp3-asi.c */
extern u8 sdi_CheckFree(struct tbs_pcie_dev *dev,int asi_base_addr, unsigned char OpbyteNum);
extern bool sdi_chip_reset(struct tbs_pcie_dev *dev,int asi_base_addr);
extern int sdi_read16bit(struct tbs_pcie_dev *dev,int asi_base_addr,int reg_addr);
extern bool sdi_write16bit(struct tbs_pcie_dev *dev,int asi_base_addr, int reg_addr, int data16bit);

#endif
