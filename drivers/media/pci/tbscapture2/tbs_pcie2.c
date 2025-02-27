/*
    TurboSight PCIex2 HDMI capture cards driver
    Copyright (C) 2024 www.tbsdtv.com
*/

#include <linux/pci.h>
#include "tbs_pcie2-reg.h"
#include "tbs_pcie2.h"
#include "libyuv.h"

static int debug=0;
module_param(debug,int,0660);

static bool enable_msi = true;//false;
module_param(enable_msi, bool, 0444);
MODULE_PARM_DESC(enable_msi, "use an msi interrupt if available");

static int tbs_get_video_param(struct tbs_video *pvideo);
static void audio_wake_process(struct work_struct *p_work);
static void video_wake_process(struct work_struct *p_work);
static void i2c_wake_process(struct work_struct *p_work);
static int ProcessStreamThread(void *data);
struct workqueue_struct *wq;
u8 fw7611[]=
{
	0x98, 0xF4, 0x80 , //CEC
	0x98, 0xF5, 0x7C , //INFOFRAME
	0x98, 0xF8, 0x4C , //DPLL
	0x98, 0xF9, 0x64 ,// KSV
	0x98, 0xFA, 0x6C , //EDID
	0x98, 0xFB, 0x68, // HDMI
	0x98, 0xFD, 0x44 ,// CP
	0x98, 0x01, 0x06 , //Prim_Mode =110b HDMI-GR
	0x98, 0x02, 0xF5 , //Auto CSC, YCrCb out, Set op_656 bit

	0x98, 0x03, 0x80 , //0x80 - 16-bit ITU-656 SDR mode
	//0x98, 0x03, 0x8a , //24 bit SDR 444 Mode 0 //0x8A - 24-bit ITU-656 SDR mode 2
	0x98, 0x04, 0x60 ,  //27M 2019-07-03 1734

	//0x98, 0x05, 0x28 , //AV Codes Off  28 ;eric 2017-11-27
	0x98, 0x05, 0x2c , //AV Codes On  2c  hanly

	0x98, 0x06, 0xA4 ,// A4 Invert VS,HS pins //test only; p signal
	//0x98, 0x06, 0x26, //eric mark, field; ok;
	//0x98, 0x06, 0x24, //eric mark, field; ok; I signal

	0x98, 0x0B, 0x44 , //Power up part
	0x98, 0x0C, 0x42 , //Power up part
	0x98, 0x14, 0x7F , //Max Drive Strength
	0x98, 0x15, 0x80 , //Disable Tristate of Pins
	0x98, 0x19, 0x83 , //LLC DLL phase
	0x98, 0x33, 0x40 , //LLC DLL enable
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
	0xff
};

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
static void i2c_write_tab_new(struct i2c_adapter *adapter, u8 *script)
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
	//printk( "%s() \n", __func__);

	sprintf(cap->driver, KBUILD_MODNAME);
	sprintf(cap->card, "video %d",(videodev->index>>1));
	sprintf(cap->bus_info, "PCI:%s %d",pci_name(videodev->dev->pdev),(videodev->index>>1));

	return 0;
}


static int tbs_vidioc_enum_fmt_vid_cap(struct file *file, void *priv_fh,struct v4l2_fmtdesc *fmt)
{
//	printk( "%s() index:%d\n", __func__,fmt->index);
	switch (fmt->index) {
	case 0:
		strncpy(fmt->description, "NV12", sizeof(fmt->description));
		fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		fmt->pixelformat = V4L2_PIX_FMT_NV12;
		break;
	case 1:
		strncpy(fmt->description, "YU12", sizeof(fmt->description));
		fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		fmt->pixelformat = V4L2_PIX_FMT_YUV420;
		break;
	case 2:
		strncpy(fmt->description, "YV12", sizeof(fmt->description));
		fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		fmt->pixelformat = V4L2_PIX_FMT_YVU420;
		break;
	case 3:
		strncpy(fmt->description, "UYVY", sizeof(fmt->description));
		fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		fmt->pixelformat = V4L2_PIX_FMT_UYVY;
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

	//printk( "%s() width:%d heigh:%d size:%d pixelformat:%x\n", __func__,pix->width,pix->height,pix->sizeimage,pix->pixelformat);

	fmt->type=V4L2_BUF_TYPE_VIDEO_CAPTURE;
	pix->width = videodev->dst_width ;
	pix->height = videodev->dst_height;
	pix->field = V4L2_FIELD_NONE;
	pix->bytesperline = videodev->dst_width ;
	pix->sizeimage = 3*(pix->width>>1) * pix->height;
	pix->colorspace = V4L2_COLORSPACE_SMPTE170M;
	pix->pixelformat = V4L2_PIX_FMT_NV12;

	return 0;
}

static int tbs_vidioc_try_fmt_vid_cap(struct file *file, void *fh, struct v4l2_format *fmt)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct v4l2_pix_format *pix = &fmt->fmt.pix;

//	printk( "%s() width:%d heigh:%d size:%d pixelformat:%x\n", __func__,pix->width,pix->height,pix->sizeimage,pix->pixelformat);

	fmt->type=V4L2_BUF_TYPE_VIDEO_CAPTURE;
	pix->width = videodev->dst_width ;
	pix->height = videodev->dst_height;
	pix->field = V4L2_FIELD_NONE;
	pix->bytesperline = videodev->dst_width ;
	pix->sizeimage = 3*(pix->width>>1) * pix->height;
	pix->colorspace = V4L2_COLORSPACE_SMPTE170M;
	pix->pixelformat = V4L2_PIX_FMT_NV12;

	
	return 0;
}

static int vidioc_s_fmt_vid_cap(struct file *file, void *priv,struct v4l2_format *fmt)
{
//	struct tbs_video *videodev = video_drvdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	struct v4l2_pix_format *pix = &fmt->fmt.pix;

	//printk( "%s() width:%d heigh:%d size:%d pixelformat:%x\n", __func__,pix->width,pix->height,pix->sizeimage,pix->pixelformat);

	file_instance->select_width=pix->width;
	file_instance->select_height=pix->height;
	file_instance->select_pixelformat=pix->pixelformat;

	if(pix->width<DEFAULT_WIDTH || pix->height<DEFAULT_HEIGH ||
		pix->width > 1920 || pix->height >1080 )
	{
		file_instance->select_width=DEFAULT_WIDTH;
		file_instance->select_height=DEFAULT_HEIGH;
		return -EINVAL;
	}

	return 0;
}


// static int tbs_vidioc_g_parm(struct file *file,void *fh, struct v4l2_streamparm *setfps)
// {
// 	struct tbs_video *videodev = video_drvdata(file);
// 	printk( "%s() fps:%x\n", __func__, videodev->fps);
//     setfps->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
//     setfps->parm.capture.timeperframe.numerator=1;
//     setfps->parm.capture.timeperframe.denominator=videodev->fps;
// 	return 0;	
// }

static	int tbs_vidioc_querystd(struct file *file, void *fh, v4l2_std_id *std)
{
//	struct tbs_video *videodev = video_drvdata(file);
	//printk( "%s()\n", __func__);
	*std= TBS_NORMS;
	return 0;
}

static int tbs_vidioc_g_std(struct file *file, void *priv, v4l2_std_id *std)
{
	struct tbs_video *videodev = video_drvdata(file);
	//printk( "%s()\n", __func__);
	*std = videodev->std;
	return 0;
}

static int tbs_vidioc_s_std(struct file *file, void *priv,v4l2_std_id std)
{
	struct tbs_video *videodev = video_drvdata(file);
	//printk( "%s()\n", __func__);
	videodev->std = std;
	return 0;
}


static int tbs_vidioc_enum_input(struct file *file, void *priv,struct v4l2_input *i)
{
	//printk( "%s()\n", __func__);

	i->type = V4L2_INPUT_TYPE_CAMERA;
	strcpy(i->name, KBUILD_MODNAME);
	i->std = TBS_NORMS;	
	if(i->index)
		return -EINVAL;
	return 0;
}

static int tbs_vidioc_g_input(struct file *file, void *priv, unsigned int *i)
{
	//printk( "%s()\n", __func__);
	*i = 0;
	return 0;
}

static int tbs_vidioc_s_input(struct file *file, void *priv, unsigned int i)
{
	//printk( "%s()\n", __func__);
	return i ? -EINVAL : 0;
}

// static int vidioc_log_status(struct file *file, void *priv)
// {
// 	printk( "%s()\n", __func__);
// 	return 0;
// }



static int tbs_queue_setup(struct vb2_queue *q,
			   unsigned int *num_buffers, unsigned int *num_planes,
			   unsigned int sizes[], struct device *alloc_devs[])
{
	u32 size;
	struct tbs_videofile_instance *stream= list_entry(q,struct tbs_videofile_instance,queue);
	//printk( "%s() vb2_queue:%p select_width:%d select_height:%d\n", __func__,q,stream->select_width,stream->select_height);
	//printk( "%s() num_buffers:%d num_planes:%d sizes[0]:%d sizes[1]:%d sizes[2]:%d\n", __func__,*num_buffers,*num_planes,sizes[0],sizes[1],sizes[2]);

	if(stream->select_pixelformat == V4L2_PIX_FMT_UYVY){
		size = 2*stream->select_width*stream->select_height;  
	}

	if(stream->select_pixelformat == V4L2_PIX_FMT_YUV420 ||
		stream->select_pixelformat == V4L2_PIX_FMT_NV12 ||
		stream->select_pixelformat == V4L2_PIX_FMT_YVU420){
			size = 3*(stream->select_width>>1)*stream->select_height;  
	}

	if (*num_planes)
		return sizes[0] < size ? -EINVAL : 0;

	*num_planes = 1;

	if(*num_buffers<2)
		*num_buffers=2;
		
	sizes[0]= size;

	return 0;

}

static int tbs_buffer_prepare(struct vb2_buffer *vb)
{
	struct tbs_videofile_instance *stream= list_entry(vb->vb2_queue,struct tbs_videofile_instance,queue);
	u32 size;


	if(stream->select_pixelformat == V4L2_PIX_FMT_UYVY){
		size = 2*stream->select_width*stream->select_height;  
	}

	if(stream->select_pixelformat == V4L2_PIX_FMT_YUV420 ||
	stream->select_pixelformat == V4L2_PIX_FMT_NV12 ||
	stream->select_pixelformat == V4L2_PIX_FMT_YVU420){
		size = 3*(stream->select_width>>1)*stream->select_height;  
	}
	
//	printk( "%s() vb2_plane_size:%ld size:%d\n", __func__,vb2_plane_size(vb,0), size);

	if (vb2_plane_size(vb, 0) < size)
		return -EINVAL;


	vb2_set_plane_payload(vb, 0, size);
	return 0;	
}

static void tbs_buffer_finish(struct vb2_buffer *vb)
{
//	printk( "%s()\n", __func__);
	return;
}

static void tbs_buffer_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
//	struct tbs_video *videodev = vb->vb2_queue->drv_priv;
	struct tbs_videofile_instance *stream= list_entry(vb->vb2_queue,struct tbs_videofile_instance,queue);
	struct tbsvideo_buffer *buf =
		container_of(vbuf, struct tbsvideo_buffer, vb);
	
//	printk( "%s()\n", __func__);
	
	spin_lock(&stream->slock);	
	list_add_tail(&buf->queue, &stream->list);
	spin_unlock(&stream->slock);	
}

static void start_video_dma_transfer(struct tbs_video *videodev)
{
	struct tbs_pcie_dev *dev =videodev->dev;

//	printk( "%s() addr:%x  index:%x \n", __func__,TBS_DMA_BASE(videodev->index),videodev->index);

	mutex_lock(&dev->devicemutex);
	TBS_PCIE_READ(TBS_DMA_BASE(videodev->index), TBS_DMA_STATUS);// clear status;
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(videodev->index), 0x00000001); //start dma;
	// write picture size
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_CELL_SIZE, DMA_VIDEO_CELL); 

	//set dma address:
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW, videodev->dmabuf[0].dma);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW1, videodev->dmabuf[1].dma);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_ADDR_LOW2, videodev->dmabuf[2].dma);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_START, 0x00000001);
	mutex_unlock(&dev->devicemutex);
}


static void stop_video_dma_transfer(struct tbs_video *videodev)
{
	struct tbs_pcie_dev *dev =videodev->dev;
	mutex_lock(&dev->devicemutex);
	TBS_PCIE_READ(TBS_DMA_BASE(videodev->index), TBS_DMA_STATUS);	
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(videodev->index), 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE(videodev->index), TBS_DMA_START, 0x00000000);	
	mutex_unlock(&dev->devicemutex);
}

static int tbs_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct tbs_video *videodev = q->drv_priv;
	struct tbs_videofile_instance *stream= list_entry(q,struct tbs_videofile_instance,queue);
	//printk( "%s() index:%x bufsize:%ld buf_struct_size:%d\n", __func__, videodev->index,sizeof(struct tbsvideo_buffer),q->buf_struct_size);

	stream->seqnr = 0;	
	stream->stream_thread = kthread_run(ProcessStreamThread,q,"tbs_stream_thread");

	return 0;
}

static void tbs_stop_streaming(struct vb2_queue *q)
{
	struct tbs_video *videodev = q->drv_priv;
	struct tbs_videofile_instance *stream= list_entry(q,struct tbs_videofile_instance,queue);
	
	//printk( "%s() index:%x \n", __func__, videodev->index);

	if(stream->stream_thread){
		kthread_stop(stream->stream_thread);
		stream->stream_thread=NULL;
	}	
	vb2_wait_for_all_buffers(q);

	//printk( "%s() exit\n", __func__);
	
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

#if 0
static void vb2_set_flags_and_caps(struct vb2_queue *q, u32 memory,
				   u32 *flags, u32 *caps, u32 *max_num_bufs)
{
	if (!q->allow_cache_hints || memory != V4L2_MEMORY_MMAP) {
		/*
		 * This needs to clear V4L2_MEMORY_FLAG_NON_COHERENT only,
		 * but in order to avoid bugs we zero out all bits.
		 */
		*flags = 0;
	} else {
		/* Clear all unknown flags. */
		*flags &= V4L2_MEMORY_FLAG_NON_COHERENT;
	}

	*caps |= V4L2_BUF_CAP_SUPPORTS_ORPHANED_BUFS;
	if (q->io_modes & VB2_MMAP)
		*caps |= V4L2_BUF_CAP_SUPPORTS_MMAP;
	if (q->io_modes & VB2_USERPTR)
		*caps |= V4L2_BUF_CAP_SUPPORTS_USERPTR;
	if (q->io_modes & VB2_DMABUF)
		*caps |= V4L2_BUF_CAP_SUPPORTS_DMABUF;
	if (q->subsystem_flags & VB2_V4L2_FL_SUPPORTS_M2M_HOLD_CAPTURE_BUF)
		*caps |= V4L2_BUF_CAP_SUPPORTS_M2M_HOLD_CAPTURE_BUF;
	if (q->allow_cache_hints && q->io_modes & VB2_MMAP)
		*caps |= V4L2_BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS;
	if (q->supports_requests)
		*caps |= V4L2_BUF_CAP_SUPPORTS_REQUESTS;
	if (max_num_bufs) {
		*max_num_bufs = q->max_num_buffers;
		*caps |= V4L2_BUF_CAP_SUPPORTS_MAX_NUM_BUFFERS;
	}
}


static int  tbs_vidioc_reqbufs(struct file *file, void *priv,
			  struct v4l2_requestbuffers *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	int res = vb2_verify_memory_type(&file_instance->queue, p->memory, p->type);
	u32 flags = p->flags;
	printk( "%s() priv:%p\n", __func__,priv);
	vb2_set_flags_and_caps(&(file_instance->queue), p->memory, &flags,
			       &p->capabilities, NULL);
	p->flags = flags;
	if (res)
		return res;
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	res = vb2_core_reqbufs(&file_instance->queue, p->memory, p->flags, &p->count);
	/* If count == 0, then the owner has released all buffers and he
	   is no longer owner of the queue. Otherwise we have a new owner. */
	if (res == 0)
		file_instance->queue.owner = p->count ? file->private_data : NULL;
	return res;
}

static int  tbs_vidioc_create_bufs(struct file *file, void *priv,
			  struct v4l2_create_buffers *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	int res = vb2_verify_memory_type(&file_instance->queue, p->memory, p->format.type);
	printk( "%s() priv:%p\n", __func__,priv);
	p->index = vb2_get_num_buffers(&file_instance->queue);
	vb2_set_flags_and_caps(&file_instance->queue, p->memory, &p->flags,
			       &p->capabilities, &p->max_num_buffers);
	/*
	 * If count == 0, then just check if memory and type are valid.
	 * Any -EBUSY result from vb2_verify_memory_type can be mapped to 0.
	 */
	if (p->count == 0)
		return res != -EBUSY ? res : 0;
	if (res)
		return res;
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;

	res = vb2_create_bufs(&file_instance->queue, p);
	if (res == 0)
		file_instance->queue.owner = file->private_data;
	return res;
}


static int  tbs_vidioc_prepare_buf(struct file *file, void *priv,
			  struct v4l2_buffer *p)
{
	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	printk( "%s() priv:%p\n", __func__,priv);
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_prepare_buf(&file_instance->queue, vdev->v4l2_dev->mdev, p);
}


static int  tbs_vidioc_querybuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	printk( "%s() priv:%p\n", __func__,priv);
	/* No need to call vb2_queue_is_busy(), anyone can query buffers. */
	return vb2_querybuf(&file_instance->queue, p);
}


static int  tbs_vidioc_qbuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

//	printk( "%s() priv:%p\n", __func__,priv);
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_qbuf(&file_instance->queue, vdev->v4l2_dev->mdev, p);
}


static int  tbs_vidioc_dqbuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
//	printk( "%s() priv:%p\n", __func__,priv);
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_dqbuf(&file_instance->queue, p, file->f_flags & O_NONBLOCK);
}

static int  tbs_vidioc_streamon(struct file *file, void *priv, enum v4l2_buf_type i)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	printk( "%s() priv:%p\n", __func__,priv);
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_streamon(&file_instance->queue, i);
}

static int  tbs_vidioc_streamoff(struct file *file, void *priv, enum v4l2_buf_type i)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	printk( "%s() priv:%p\n", __func__,priv);
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_streamoff(&file_instance->queue, i);
}
#else

static void fill_buf_caps(struct vb2_queue *q, u32 *caps)
{
	*caps = V4L2_BUF_CAP_SUPPORTS_ORPHANED_BUFS;
	if (q->io_modes & VB2_MMAP)
		*caps |= V4L2_BUF_CAP_SUPPORTS_MMAP;
	if (q->io_modes & VB2_USERPTR)
		*caps |= V4L2_BUF_CAP_SUPPORTS_USERPTR;
	if (q->io_modes & VB2_DMABUF)
		*caps |= V4L2_BUF_CAP_SUPPORTS_DMABUF;
	if (q->subsystem_flags & VB2_V4L2_FL_SUPPORTS_M2M_HOLD_CAPTURE_BUF)
		*caps |= V4L2_BUF_CAP_SUPPORTS_M2M_HOLD_CAPTURE_BUF;
	if (q->allow_cache_hints && q->io_modes & VB2_MMAP)
		*caps |= V4L2_BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS;
#ifdef CONFIG_MEDIA_CONTROLLER_REQUEST_API
	if (q->supports_requests)
		*caps |= V4L2_BUF_CAP_SUPPORTS_REQUESTS;
#endif
}

static void validate_memory_flags(struct vb2_queue *q,
				  int memory,
				  u32 *flags)
{
	if (!q->allow_cache_hints || memory != V4L2_MEMORY_MMAP) {
		/*
		 * This needs to clear V4L2_MEMORY_FLAG_NON_COHERENT only,
		 * but in order to avoid bugs we zero out all bits.
		 */
		*flags = 0;
	} else {
		/* Clear all unknown flags. */
		*flags &= V4L2_MEMORY_FLAG_NON_COHERENT;
	}
}

static int  tbs_vidioc_reqbufs(struct file *file, void *priv,
			  struct v4l2_requestbuffers *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	int res = vb2_verify_memory_type(&file_instance->queue, p->memory, p->type);
	u32 flags = p->flags;

	fill_buf_caps(&file_instance->queue, &p->capabilities);
	validate_memory_flags(&file_instance->queue, p->memory, &flags);
	p->flags = flags;
	if (res)
		return res;
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	res = vb2_core_reqbufs(&file_instance->queue, p->memory, p->flags, &p->count);
	/* If count == 0, then the owner has released all buffers and he
	   is no longer owner of the queue. Otherwise we have a new owner. */
	if (res == 0)
		file_instance->queue.owner = p->count ? file->private_data : NULL;
	return res;
}

static int  tbs_vidioc_create_bufs(struct file *file, void *priv,
			  struct v4l2_create_buffers *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);
	int res = vb2_verify_memory_type(&file_instance->queue, p->memory,
			p->format.type);

	p->index = file_instance->queue.num_buffers;
	fill_buf_caps(&file_instance->queue, &p->capabilities);
	validate_memory_flags(&file_instance->queue, p->memory, &p->flags);
	/*
	 * If count == 0, then just check if memory and type are valid.
	 * Any -EBUSY result from vb2_verify_memory_type can be mapped to 0.
	 */
	if (p->count == 0)
		return res != -EBUSY ? res : 0;
	if (res)
		return res;
	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;

	res = vb2_create_bufs(&file_instance->queue, p);
	if (res == 0)
		file_instance->queue.owner = file->private_data;
	return res;
}

static int  tbs_vidioc_prepare_buf(struct file *file, void *priv,
			  struct v4l2_buffer *p)
{
	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_prepare_buf(&file_instance->queue, vdev->v4l2_dev->mdev, p);
}

static int  tbs_vidioc_querybuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

	/* No need to call vb2_queue_is_busy(), anyone can query buffers. */
	return vb2_querybuf(&file_instance->queue, p);
}

static int  tbs_vidioc_qbuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_qbuf(&file_instance->queue, vdev->v4l2_dev->mdev, p);
}

static int  tbs_vidioc_dqbuf(struct file *file, void *priv, struct v4l2_buffer *p)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_dqbuf(&file_instance->queue, p, file->f_flags & O_NONBLOCK);
}

static int  tbs_vidioc_streamon(struct file *file, void *priv, enum v4l2_buf_type i)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_streamon(&file_instance->queue, i);
}

static int  tbs_vidioc_streamoff(struct file *file, void *priv, enum v4l2_buf_type i)
{
//	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(priv, struct tbs_videofile_instance, fh);

	if (vb2_queue_is_busy(&file_instance->queue, file))
		return -EBUSY;
	return vb2_streamoff(&file_instance->queue, i);
}

#endif

static int tbs_vidioc_get_ctrl(struct file *file, void *fh,
			        struct v4l2_tbs_data * data)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct tbs_pcie_dev *dev = videodev->dev;
	data->value  = TBS_PCIE_READ(data->baseaddr, data->reg);
	//printk("read :baseaddr=0x%x, reg=0x%x, value=0x%x\n", data->baseaddr, data->reg, data->value);
	return 0;
}
static int tbs_vidioc_set_ctrl(struct file *file, void *fh,
			        struct v4l2_tbs_data * data)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct tbs_pcie_dev *dev = videodev->dev;
	//printk("write: baseaddr=0x%x, reg=0x%x, value=0x%x\n", data->baseaddr, data->reg, data->value);
	TBS_PCIE_WRITE(data->baseaddr,data->reg,data->value);
	return 0;
}
static const struct v4l2_ioctl_ops tbs_ioctl_fops = {
	.vidioc_querycap = tbs_vidioc_querycap,

	.vidioc_enum_fmt_vid_cap = tbs_vidioc_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap = tbs_vidioc_g_fmt_vid_cap,
//	.vidioc_g_fmt_vid_cap = tbs_vidioc_g_fmt_vid_cap_mplane,
	.vidioc_try_fmt_vid_cap = tbs_vidioc_try_fmt_vid_cap,
//	.vidioc_try_fmt_vid_cap = tbs_vidioc_try_fmt_vid_cap_mplane,
	.vidioc_s_fmt_vid_cap = vidioc_s_fmt_vid_cap,
//	.vidioc_s_fmt_vid_cap = vidioc_s_fmt_vid_cap_mplane,

	// .vidioc_reqbufs       = vb2_ioctl_reqbufs,
	// .vidioc_prepare_buf   = vb2_ioctl_prepare_buf,
	// .vidioc_create_bufs   = vb2_ioctl_create_bufs,
	// .vidioc_querybuf      = vb2_ioctl_querybuf,
	// .vidioc_qbuf          = vb2_ioctl_qbuf,
	// .vidioc_dqbuf         = vb2_ioctl_dqbuf,
	// .vidioc_streamon      = vb2_ioctl_streamon,
	// .vidioc_streamoff     = vb2_ioctl_streamoff,
	

	.vidioc_reqbufs       = tbs_vidioc_reqbufs,
	.vidioc_prepare_buf   = tbs_vidioc_prepare_buf,
	.vidioc_create_bufs   = tbs_vidioc_create_bufs,
	.vidioc_querybuf      = tbs_vidioc_querybuf,
	.vidioc_qbuf          = tbs_vidioc_qbuf,
	.vidioc_dqbuf         = tbs_vidioc_dqbuf,
	.vidioc_streamon      = tbs_vidioc_streamon,
	.vidioc_streamoff     = tbs_vidioc_streamoff,

	.vidioc_querystd = tbs_vidioc_querystd,
	.vidioc_g_std = tbs_vidioc_g_std,
	.vidioc_s_std = tbs_vidioc_s_std,

	.vidioc_enum_input = tbs_vidioc_enum_input,
	.vidioc_g_input = tbs_vidioc_g_input,
	.vidioc_s_input = tbs_vidioc_s_input,

//	.vidioc_log_status = vidioc_log_status,
	.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
//	.vidioc_g_parm = tbs_vidioc_g_parm,
	.vidioc_tbs_g_ctrls = tbs_vidioc_get_ctrl,
	.vidioc_tbs_s_ctrls = tbs_vidioc_set_ctrl,
};


static int tbs_open(struct file *file)
{
	struct tbs_video *videodev = video_drvdata(file);
	unsigned char * filebuf=NULL;
	struct tbs_videofile_instance *file_instance;
	struct vb2_queue *vb_q ;
	int err;

	//printk( "%s() index:%x entry\n", __func__,videodev->index);
	tbs_get_video_param(videodev);
	if(videodev->dst_width<=DEFAULT_WIDTH || videodev->height <= DEFAULT_HEIGH){
		//printk(KERN_ERR "%s  1 \n", __func__);
		//return -1;
	}

	filebuf = kvmalloc(FILE_INSTANCE_SIZE,GFP_KERNEL);
	if(!filebuf){
		printk(KERN_ERR "%s  2 \n", __func__);
		return -1;	
	}

	//memset((void*)filebuf,0,FILE_INSTANCE_SIZE);

	file_instance   = kzalloc(sizeof (struct tbs_videofile_instance), GFP_KERNEL);
	if(!file_instance){
		printk(KERN_ERR "%s  3 \n", __func__);
		kvfree(filebuf);
		return -1;
	}

	mutex_init(&(file_instance->queue_lock));
	INIT_LIST_HEAD(&file_instance->list);
	spin_lock_init(&file_instance->slock);	
	v4l2_fh_init(&file_instance->fh, &videodev->vdev);
	v4l2_fh_add(&file_instance->fh);
	file_instance->imgbuf0 = filebuf;
	file_instance->imgbuf1 = filebuf+DMA_VIDEO_TOTAL;
	vb_q = &(file_instance->queue);
	vb_q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	vb_q->io_modes = VB2_MMAP|VB2_DMABUF|VB2_READ|VB2_USERPTR;
	//vb_q->min_queued_buffers=1;
	vb_q->min_buffers_needed=1;
	vb_q->drv_priv = videodev;
	vb_q->buf_struct_size = sizeof(struct tbsvideo_buffer);
	vb_q->ops = &tbspcie_video_qops;
	vb_q->mem_ops = &vb2_vmalloc_memops;
//	vb_q->mem_ops = &vb2_dma_sg_memops;
//	vb_q->mem_ops = &vb2_dma_contig_memops;

	vb_q->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
//	vb_q->gfp_flags=GFP_HIGHUSER;
	vb_q->lock = &(file_instance->queue_lock);
	vb_q->dev = &(videodev->dev->pdev->dev);

	err = vb2_queue_init(vb_q);
	if(err != 0){
		printk(KERN_ERR " vb2_queue_init failed !!!!! \n");
		v4l2_fh_del(&file_instance->fh);       
		kvfree(filebuf);
		kfree(file_instance);
		return -1;	
	}

	file->private_data = &file_instance->fh;

	videodev->runstatus++;
	videodev->dev->signal_ready=1;
	wake_up(&videodev->dev->wq);

	//printk( "%s() index:%x  success \n", __func__,videodev->index);
	return 0;		
}

static int tbs_close(struct file *file)
{
	struct tbs_video *videodev = video_drvdata(file);
	struct tbs_videofile_instance *file_instance;
	file_instance = container_of(file->private_data, struct tbs_videofile_instance, fh);

	//printk( "%s() index:%x \n", __func__,videodev->index);
	
	if(videodev->runstatus>0)	
		videodev->runstatus--;	

	if(file_instance){
		vb2_queue_release(&file_instance->queue);
		if(file_instance->imgbuf0){
			kvfree(file_instance->imgbuf0);
			file_instance->imgbuf0=NULL;
			file_instance->imgbuf1=NULL;
		}
		v4l2_fh_del(&file_instance->fh);        
		kfree(file_instance);

	}

	return 0;		
}

static int tbs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct tbs_videofile_instance *file_instance;
	file_instance = container_of(file->private_data, struct tbs_videofile_instance, fh);
	//printk( "%s() \n", __func__);
	return vb2_mmap(&file_instance->queue, vma);
}

static __poll_t tbs_poll(struct file *file, poll_table *wait)
{
	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(file->private_data, struct tbs_videofile_instance, fh);
	struct vb2_queue *q = &file_instance->queue;
	struct mutex *lock = q->lock ? q->lock : vdev->lock;
	__poll_t res;
	void *fileio;

	/*
	 * If this helper doesn't know how to lock, then you shouldn't be using
	 * it but you should write your own.
	 */
	WARN_ON(!lock);

	if (lock && mutex_lock_interruptible(lock))
		return EPOLLERR;

	fileio = q->fileio;

	res = vb2_poll(q, file, wait);

	/* If fileio was started, then we have a new queue owner. */
	if (!fileio && q->fileio)
		q->owner = file->private_data;
	if (lock)
		mutex_unlock(lock);
	return res;
}


static ssize_t tbs_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	struct video_device *vdev = video_devdata(file);
	struct tbs_videofile_instance *file_instance = container_of(file->private_data, struct tbs_videofile_instance, fh);
	struct mutex *lock = file_instance->queue.lock ? file_instance->queue.lock : vdev->lock;
	int err = -EBUSY;

	if (!(file_instance->queue.io_modes & VB2_READ))
		return -EINVAL;
	if (lock && mutex_lock_interruptible(lock))
		return -ERESTARTSYS;
	if (vb2_queue_is_busy(&file_instance->queue, file))
		goto exit;
	file_instance->queue.owner = file->private_data;
	err = vb2_read(&file_instance->queue, buf, count, ppos,
		       file->f_flags & O_NONBLOCK);
	if (!file_instance->queue.fileio)
		file_instance->queue.owner = NULL;
exit:
	if (lock)
		mutex_unlock(lock);
	return err;
}

static const struct v4l2_file_operations tbs_fops = {
	.owner		= THIS_MODULE,
	.open		= tbs_open,//v4l2_fh_open,
	.release	= tbs_close,
	.read		= tbs_read,
	.poll		= tbs_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap           = tbs_mmap,
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
	//if (TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL) == 1);
	TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
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
	//if (TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL) == 1);
	TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
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

	//if (TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL) == 1);
	TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
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



	for (i = 0; i < INTERFACES; i++) {
		i2c = &dev->i2c_bus[i];
		i2c->dev = dev;
		i2c->i2c_dev = i;

		INIT_WORK(&i2c->i2cwork,i2c_wake_process);

		init_waitqueue_head(&i2c->wq);

		adap = &i2c->i2c_adap;
		i2c_set_adapdata(adap, i2c);

		sprintf(adap->name,"tbs_i2c_%d",i);

		adap->algo = &tbs_i2c_algo;
		adap->algo_data = dev;
		adap->dev.parent = &dev->pdev->dev;

		err = i2c_add_adapter(adap);
		if (err)
			goto fail;
	}

	/* enable i2c interrupts */
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_0, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_1, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_2, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_3, 0x00000001);

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

	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000000);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_0, 0x00000000);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_1, 0x00000000);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_2, 0x00000000);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_3, 0x00000000);

	for (i = 0; i < INTERFACES; i++) {
		i2c = &dev->i2c_bus[i];
		adap = &i2c->i2c_adap;
		i2c_del_adapter(adap);
	}
}


static irqreturn_t tbs_pcie_irq(int irq, void *dev_id)
{
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev *) dev_id;
	struct tbs_i2c *i2c;
	u32 stat;
	u32 ret;
	unsigned char index;

	stat = TBS_PCIE_READ(TBS_INT_BASE, TBS_INT_STATUS);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_STATUS, stat);

	if ((stat & 0x00000fff) == 0)
	{
		TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001); 
		return IRQ_NONE;
	}

//	printk( "%s(): stat:%x \n", __func__, stat);


//hdmi interface 0

	if (stat & 0x00000010){ //audio 0
		ret = TBS_PCIE_READ(TBS_DMA_BASE_0, 0);
		//printk( "%s(): audio 0 %x \n", __func__, ret);
		index = (ret)&(TBS_AUDIO_CELLS-1);
		dev->audio[0].pos = index *TBS_AUDIO_CELL_SIZE;
		snd_pcm_period_elapsed(dev->audio[0].substream);
		//queue_work(wq,&dev->audio[0].audiowork);
	}

	if (stat & 0x00000020){//video 0
		dev->video[0].videostatus= TBS_PCIE_READ(TBS_DMA_BASE_1, 0);
		//printk( "%s(): video 0 %x \n", __func__, dev->video[0].videostatus);
		if(dev->video[0].Interlaced){
			if(dev->video[0].videostatus & 0x1000000){
				queue_work(wq,&dev->video[0].videowork);
			}
		}else{
				queue_work(wq,&dev->video[0].videowork);
		}
	}

//hdmi interface 1

	if (stat & 0x00000040){ //audio 1
		ret = TBS_PCIE_READ(TBS_DMA_BASE_2, 0);
		//printk( "%s(): audio 1 %x \n", __func__, ret);
		index = (ret)&(TBS_AUDIO_CELLS-1);
		dev->audio[1].pos = index *TBS_AUDIO_CELL_SIZE;
		snd_pcm_period_elapsed(dev->audio[1].substream);
		//queue_work(wq,&dev->audio[1].audiowork);
	}

	if (stat & 0x00000080){//video 1
		dev->video[1].videostatus = TBS_PCIE_READ(TBS_DMA_BASE_3, 0);
		//printk( "%s(): video 1 %x \n", __func__, dev->video[1].videostatus);
		if(dev->video[1].Interlaced){
			if(dev->video[1].videostatus & 0x1000000){
				queue_work(wq,&dev->video[1].videowork);				
			}

		}else{
				queue_work(wq,&dev->video[1].videowork);				
		}
	}

//hdmi interface 2

	if (stat & 0x00000100){ //audio 2
		ret = TBS_PCIE_READ(TBS_DMA_BASE_4, 0);
		//printk( "%s(): audio 2 %x \n", __func__, ret);
		index = (ret)&(TBS_AUDIO_CELLS-1);
		dev->audio[2].pos = index *TBS_AUDIO_CELL_SIZE;
		snd_pcm_period_elapsed(dev->audio[2].substream);
		//queue_work(wq,&dev->audio[2].audiowork);
	}

	if (stat & 0x00000200){//video 2
		dev->video[2].videostatus = TBS_PCIE_READ(TBS_DMA_BASE_5, 0);
		//printk( "%s(): video 2 %x \n", __func__, dev->video[2].videostatus);
		if(dev->video[2].Interlaced){
			if(dev->video[2].videostatus & 0x1000000){
				queue_work(wq,&dev->video[2].videowork);				
			}

		}else{
				queue_work(wq,&dev->video[2].videowork);				
		}
	}
	
//hdmi interface 3

	if (stat & 0x00000400){ //audio 3
		ret = TBS_PCIE_READ(TBS_DMA_BASE_6, 0);
		//printk( "%s(): audio 3 %x \n", __func__, ret);
		index = (ret)&(TBS_AUDIO_CELLS-1);
		dev->audio[3].pos = index *TBS_AUDIO_CELL_SIZE;
		snd_pcm_period_elapsed(dev->audio[3].substream);
		//queue_work(wq,&dev->audio[3].audiowork);
	}

	if (stat & 0x00000800){//video 3
		dev->video[3].videostatus = TBS_PCIE_READ(TBS_DMA_BASE_7, 0);
		//printk( "%s(): video 3 %x \n", __func__, dev->video[3].videostatus);
		if(dev->video[3].Interlaced){
			if(dev->video[3].videostatus & 0x1000000){
				queue_work(wq,&dev->video[3].videowork);				
			}

		}else{
				queue_work(wq,&dev->video[3].videowork);				
		}
	}
	




	if (stat & 0x00000001) {
		i2c = &dev->i2c_bus[0];
		TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
		queue_work(wq,&i2c->i2cwork);
	}
	if (stat & 0x00000002) {
		i2c = &dev->i2c_bus[1];
		TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
		queue_work(wq,&i2c->i2cwork);
	}
	if (stat & 0x00000004) {
		i2c = &dev->i2c_bus[2];
		TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
		queue_work(wq,&i2c->i2cwork);
	}
	if (stat & 0x00000008) {
		i2c = &dev->i2c_bus[3];
		TBS_PCIE_READ(i2c->base, TBS_I2C_CTRL);
		queue_work(wq,&i2c->i2cwork);
	}

	/* enable interrupt */
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);
	return IRQ_HANDLED;
}

static int tbs_get_video_param(struct tbs_video *pvideo)
{
	struct i2c_adapter *tbs_adap = &pvideo->dev->i2c_bus[pvideo->index>>1].i2c_adap ;
	struct tbs_pcie_dev		*dev = pvideo->dev;
	
    unsigned char tmp[10];
    unsigned int width;
    unsigned int height;
    unsigned int interlaced = 0;
    unsigned int tmp_B, fps = 0;

    mutex_lock(&dev->devicemutex);
    i2c_read_reg(tbs_adap, 0x98, 0x6f, tmp, 1);
    if ((tmp[0] & 0x01) == 0x1) {
        i2c_read_reg(tbs_adap, 0x68, 0x07, tmp, 2);
        width = (tmp[0] & 0x1f) * 256 + tmp[1];
        //  printk("pix:%d ", width);
        i2c_read_reg(tbs_adap,0x68, 0x09, tmp, 2);
        height = (tmp[0] & 0x1f) * 256 + tmp[1];
        // printk("line:%d \n", height);

        i2c_read_reg(tbs_adap,0x44, 0xb8, tmp, 2);
        tmp_B = ((tmp[0] & 0x1f) << 8) + tmp[1];
        if (tmp_B)
            fps = (unsigned char)((103663 + (tmp_B - 1)) / tmp_B);
          //printk("HDMI tmp_B:%x fps:%d  \n", tmp_B, fps);


        i2c_read_reg(tbs_adap, 0x68, 0x0b, tmp, 1);
        if (tmp[0] & 0x20) {
            //printk("HDMI Interlaced Input:%x  \n", tmp[0]);
            height <<= 1;
            interlaced = 1;
            tmp[0] = 0x06;
            tmp[1] = 0x24;
            i2c_write_reg(tbs_adap,  0x98, tmp, 2);
        }
        else {
            //printk("HDMI Progressive Input:%x  \n", tmp[0]);
            interlaced = 0;
            tmp[0] = 0x06;
            tmp[1] = 0xA4;
            i2c_write_reg(tbs_adap,  0x98, tmp, 2);
        }
         //printk("line:%d \n", height);

        mutex_unlock(&dev->devicemutex);
        if (width == 0 || height == 0 || height > 1080 || width > 1920) {
            //printk("HDMI cable %d image size error width:%d height:%d\n",(pvideo->index>>1),width, height);
			pvideo->dst_width=DEFAULT_WIDTH;
			pvideo->dst_height=DEFAULT_HEIGH;
			pvideo->present=0;
            return -1;
        }


    }else {
        mutex_unlock(&dev->devicemutex);
        //printk("HDMI cable %d is not connected!\n",(pvideo->index>>1));
		pvideo->dst_width=DEFAULT_WIDTH;
		pvideo->dst_height=DEFAULT_HEIGH;
		pvideo->present=0;
        return -1;
    }
    pvideo->Interlaced = interlaced;
    pvideo->fps = fps >> interlaced;
	pvideo->dst_width=
    pvideo->width = width;
	pvideo->dst_height=
    pvideo->height = height;
	pvideo->present=1;
    return 0;
}

static void tbs_adapters_reset(	struct i2c_adapter *tbs_adap)
{

	int i;
	u8 tmp[2];
	for(i=0;i<3;i++){
		//read 7611 id and init chip here
		i2c_read_reg(tbs_adap,0x98, 0xea,tmp, 2);
		printk("7611 chip id(%d) : %x, %x\n", i,tmp[0],tmp[1]);
		if((tmp[0] == 0x20)&&(tmp[1] == 0x51))
		{
			//reset
			tmp[0] = 0xff;
			tmp[1] = 0x80;
			i2c_write_reg(tbs_adap,0x98, tmp,2);
			msleep(200);//sleep

			i2c_write_tab_new(tbs_adap, fw7611);
			msleep(200);
			break;
		}	
	}		

}

static void tbs_adapters_init(struct tbs_pcie_dev *dev)
{
	struct i2c_adapter *tbs_adap;
	struct tbs_video *pvideo;
	int i;

	/* disable all interrupts */
	//TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001); 

	/* disable dma */
	TBS_PCIE_WRITE(TBS_DMA_BASE_0, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_1, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_2, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_3, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_4, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_5, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_6, TBS_DMA_START, 0x00000000);
	TBS_PCIE_WRITE(TBS_DMA_BASE_7, TBS_DMA_START, 0x00000000);	

	for (i = 0; i < INTERFACES; i++) {
		tbs_adap = &dev->i2c_bus[i].i2c_adap;
		dev->i2c_bus[i].dev = dev;
		//printk( "\n%s(): %x \n", __func__, i);
		tbs_adapters_reset(tbs_adap);
		pvideo = &dev->video[i];
		pvideo->dev=dev;
		pvideo->index = i*2+1;
		tbs_get_video_param(pvideo);
	}
}

static int tbs_video_register(struct tbs_pcie_dev *dev)
{
	struct video_device *vdev ;
	int i;
	int err=-1;

	for(i=0;i<INTERFACES;i++){

		err = v4l2_device_register(&dev->pdev->dev, &dev->video[i].v4l2_dev);
		if(err<0){
			printk(KERN_ERR " v4l2_device_register %d error! \n",i);
			goto fail;
		}

		dev->video[i].index = i*2+1;
		dev->video[i].dev = dev;	
		mutex_init(&(dev->video[i].video_lock));

		vdev = &(dev->video[i].vdev);
		vdev->queue = NULL;
		vdev->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING ;
		vdev->tvnorms =TBS_NORMS;
		vdev->vfl_dir=VFL_DIR_RX;
		vdev->vfl_type=VFL_TYPE_VIDEO;
		vdev->v4l2_dev = &(dev->video[i].v4l2_dev);
		vdev->lock = &(dev->video[i].video_lock);
		vdev->fops = &tbs_fops;
		vdev->ioctl_ops = &tbs_ioctl_fops;
		vdev->release = video_device_release_empty;
		strcpy(vdev->name,KBUILD_MODNAME);
		video_set_drvdata(vdev, &(dev->video[i]));

		INIT_WORK(&dev->video[i].videowork,video_wake_process);

		init_waitqueue_head(&dev->video[i].wq);
		
		dev->video[i].dmabuf[0].virtaddr = dma_alloc_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL, &dev->video[i].dmabuf[0].dma,GFP_DMA32);
		if (!dev->video[i].dmabuf[0].virtaddr) {
			printk(" allocate memory 0 failed\n");
			goto fail;
		}
		dev->video[i].dmabuf[1].virtaddr = dma_alloc_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL, &dev->video[i].dmabuf[1].dma,GFP_DMA32);
		if (!dev->video[i].dmabuf[1].virtaddr) {
			printk(" allocate memory 1 failed\n");
			goto fail;
		}
		dev->video[i].dmabuf[2].virtaddr = dma_alloc_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL, &dev->video[i].dmabuf[2].dma,GFP_DMA32);
		if (!dev->video[i].dmabuf[2].virtaddr) {
			printk(" allocate memory 2 failed\n");
			goto fail;
		}

		err = video_register_device(vdev, VFL_TYPE_VIDEO,-1);
		if(err!=0){
			printk(KERN_ERR " v4l2_device_register failed !!!!! \n");
			goto fail;
		}else{
			printk(" TBS6314R video %d register OK ! \n",i);
		}
	}
	return 0;
fail:
	for(i=0;i<INTERFACES;i++){
		if(dev->video[i].dmabuf[0].virtaddr){
				dma_free_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL, dev->video[i].dmabuf[0].virtaddr, dev->video[i].dmabuf[0].dma);
				dev->video[i].dmabuf[0].virtaddr =NULL;
		}
		if(dev->video[i].dmabuf[1].virtaddr){
				dma_free_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL, dev->video[i].dmabuf[1].virtaddr, dev->video[i].dmabuf[1].dma);
				dev->video[i].dmabuf[1].virtaddr =NULL;
		}
		if(dev->video[i].dmabuf[2].virtaddr){
				dma_free_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL, dev->video[i].dmabuf[2].virtaddr, dev->video[i].dmabuf[2].dma);
				dev->video[i].dmabuf[2].virtaddr =NULL;
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
	.info =  (SNDRV_PCM_INFO_INTERLEAVED |SNDRV_PCM_INFO_BLOCK_TRANSFER |SNDRV_PCM_INFO_MMAP|SNDRV_PCM_INFO_MMAP_VALID),
	.formats = (SNDRV_PCM_FMTBIT_S16_LE),
	.rates = SNDRV_PCM_RATE_KNOT | SNDRV_PCM_RATE_8000_192000,
	.rate_min = 8000,
	.rate_max = 192000,
	.channels_min = 2,
	.channels_max =2,
	.period_bytes_min = TBS_AUDIO_CELL_SIZE,
	.period_bytes_max = TBS_AUDIO_CELL_SIZE,
	.periods_min      = TBS_AUDIO_CELLS,
	.periods_max      = TBS_AUDIO_CELLS,
	.buffer_bytes_max = TBS_AUDIO_CELL_SIZE*TBS_AUDIO_CELLS,
};

static int tbs_pcie_audio_open(struct snd_pcm_substream *substream)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct i2c_adapter *tbs_adap;
	unsigned int rate,setrate=44100;
	u8 tmp[2];

	
	//printk(KERN_INFO "%s() index:%x runstatus:%d substream:%p runtime:%p \n",__func__,chip->index,chip->runstatus,substream,runtime);

//	if(chip->dev->video[chip->index>>1].present ==0)
//		return -1;

	chip->runstatus++;

	chip->substream = substream;
	runtime->hw = mycard_capture_stero;
	
	tbs_adap = &chip->dev->i2c_bus[chip->index>>1].i2c_adap;
	i2c_read_reg(tbs_adap,0x68, 0x39,tmp, 1);	
	rate = cs_data_fs[tmp[0]&15];
	if(rate)
		setrate = rate;
		
	setrate = 48000;
	
	//printk(KERN_INFO "%s() rate:%d setrate:%d tmp[0]:%d\n",__func__, rate,setrate,tmp[0]&15);
	snd_pcm_hw_constraint_minmax(runtime,SNDRV_PCM_HW_PARAM_RATE,setrate,setrate);
	return 0;
}

static int tbs_pcie_audio_close(struct snd_pcm_substream *substream)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	chip->runstatus--;
	//printk(KERN_INFO "%s() index:%x\n",__func__,chip->index);
	return 0;
} 
static int tbs_pcie_audio_hw_params(struct snd_pcm_substream *substream, struct snd_pcm_hw_params *hw_params)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	//printk(KERN_INFO "%s() index:%x\n",__func__,chip->index);
	return snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hw_params));
}  

static int tbs_pcie_audio_hw_free(struct snd_pcm_substream *substream)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct tbs_pcie_dev *dev= chip->dev;

	//printk(KERN_INFO "%s() index:%x\n",__func__,chip->index);

	TBS_PCIE_READ(TBS_DMA_BASE(chip->index), TBS_DMA_STATUS);	
	//stop dma
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(chip->index), 0x000000000); 
	TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_START, 0x00000000);

	return snd_pcm_lib_free_pages(substream);
} 

static int tbs_pcie_audio_prepare(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);
	struct tbs_pcie_dev *dev= chip->dev;

	//printk(KERN_INFO "%s() index:%x\n",__func__,chip->index);
	

	//set dma address:
	TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_ADDR_LOW, runtime->dma_addr);

	//write dma size
	TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_SIZE,TBS_AUDIO_CELL_SIZE*TBS_AUDIO_CELLS ); 
	// write picture size
	TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_CELL_SIZE, TBS_AUDIO_CELL_SIZE); 

	TBS_PCIE_READ(TBS_DMA_BASE(chip->index), TBS_DMA_STATUS);
	//start dma
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_DMA_MASK(chip->index), 0x00000001); 
	TBS_PCIE_WRITE(TBS_DMA_BASE(chip->index), TBS_DMA_START, 0x00000001);

	chip->pos=0;

	return 0;
}  
static int tbs_pcie_audio_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct tbs_audio *chip = snd_pcm_substream_chip(substream);

	switch(cmd){
		case SNDRV_PCM_TRIGGER_START:
			//printk(KERN_INFO "SNDRV_PCM_TRIGGER_START index:%x\n",chip->index);		
			break;
		case SNDRV_PCM_TRIGGER_STOP:			
			//printk(KERN_INFO "SNDRV_PCM_TRIGGER_STOP index:%x\n",chip->index);		
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
//	printk(KERN_INFO "%s() index:%x\n",__func__,chip->index);
	return bytes_to_frames(runtime,chip->pos);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
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
static int tbs_pcie_audio_copy(struct snd_pcm_substream *substream, int channel,
		    unsigned long pos, struct iov_iter *iter, unsigned long bytes)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int ret;
//	printk(KERN_INFO "%s() index:%x\n",__func__,chip->index);
	ret = copy_to_iter_fromio(iter,runtime->dma_area+pos,bytes);
	return 0;

};
#endif

struct snd_pcm_ops tbs_pcie_pcm_ops ={
	.open =			tbs_pcie_audio_open,
	.close = 		tbs_pcie_audio_close,
	.ioctl =		snd_pcm_lib_ioctl,
	.hw_params = 	tbs_pcie_audio_hw_params,
	.hw_free =		tbs_pcie_audio_hw_free,
	.prepare =		tbs_pcie_audio_prepare,
	.trigger =		tbs_pcie_audio_trigger,
	.pointer =		tbs_pcie_audio_pointer,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	.copy_user =	tbs_pcie_audio_copy_user,
#else
	.copy =			tbs_pcie_audio_copy,
#endif
};

static int tbs_audio_register(struct tbs_pcie_dev *dev)
{
	struct snd_card 	*card;
	int ret;
	int i;
	char audioname[100];
	for(i=0;i<INTERFACES;i++){
		sprintf(audioname,"tbsaudio%02d",i);
		ret = snd_card_new(&dev->pdev->dev, -1, audioname, THIS_MODULE,	sizeof(struct tbs_audio), &card);
		if (ret < 0){
			printk(KERN_ERR "%s() ERROR: snd_card_new failed <%d>\n",__func__, ret);
			goto fail0;
		}
		strcpy(card->driver, KBUILD_MODNAME);
		strcpy(card->shortname, audioname);
		sprintf(card->longname, "%s",audioname);

		ret = snd_pcm_new(card,audioname,0,0,1,&dev->audio[i].pcm);
		if (ret < 0){
			printk(KERN_ERR "%s() ERROR: snd_pcm_new failed <%d>\n",__func__, ret);
			goto fail1;
		}

		dev->audio[i].index=i*2;
		dev->audio[i].dev=dev;
		dev->audio[i].pcm->private_data = &dev->audio[i];		

		snd_pcm_set_ops(dev->audio[i].pcm,SNDRV_PCM_STREAM_CAPTURE,&tbs_pcie_pcm_ops);
		snd_pcm_lib_preallocate_pages_for_all(dev->audio[i].pcm, SNDRV_DMA_TYPE_DEV,&dev->pdev->dev, TBS_AUDIO_CELL_SIZE*TBS_AUDIO_CELLS, TBS_AUDIO_CELL_SIZE*TBS_AUDIO_CELLS);

		ret = snd_card_register(card);
		if ( ret < 0) {
			printk(KERN_ERR "%s() ERROR: snd_card_register failed\n",__func__);
			goto fail1;
		}
		INIT_WORK(&dev->audio[i].audiowork,audio_wake_process);

		dev->audio[i].card =card;
	}
	return 0;

fail1:
	for(i=0;i<INTERFACES;i++){
		if(dev->audio[i].pcm){
			snd_pcm_lib_preallocate_free_for_all(dev->audio[i].pcm);
		}
		dev->audio[i].pcm=NULL;
		
		if(dev->audio[i].card){
			snd_card_disconnect(dev->audio[i].card);
			snd_card_free(dev->audio[i].card);
		}			
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

	if(dev->signalthread){
		kthread_stop(dev->signalthread);
		dev->signalthread=NULL;
	}


	for(i=0;i<INTERFACES;i++){
		if(dev->audio[i].pcm){
			snd_pcm_lib_preallocate_free_for_all(dev->audio[i].pcm);
		}
		dev->audio[i].pcm=NULL;

		if(dev->audio[i].card){
			snd_card_disconnect(dev->audio[i].card);
			snd_card_free(dev->audio[i].card);
		}			
		dev->audio[i].card=NULL;
	}

	tbs_i2c_exit(dev);
	/* disable interrupts */

	for(i=0;i<INTERFACES;i++){
		if(dev->video[i].dmabuf[0].virtaddr){
				dma_free_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL,dev->video[i].dmabuf[0].virtaddr, dev->video[i].dmabuf[0].dma);
				dev->video[i].dmabuf[0].virtaddr =NULL;
		}
		if(dev->video[i].dmabuf[1].virtaddr){
				dma_free_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL,dev->video[i].dmabuf[1].virtaddr, dev->video[i].dmabuf[1].dma);
				dev->video[i].dmabuf[1].virtaddr =NULL;
		}
		if(dev->video[i].dmabuf[2].virtaddr){
				dma_free_coherent(&dev->pdev->dev,  DMA_VIDEO_TOTAL,dev->video[i].dmabuf[2].virtaddr, dev->video[i].dmabuf[2].dma);
				dev->video[i].dmabuf[2].virtaddr =NULL;
		}

		vdev = &dev->video[i].vdev;
		video_unregister_device(vdev);
		v4l2_device_unregister(&dev->video[i].v4l2_dev);
	}

	free_irq(dev->pdev->irq, dev);

	if (dev->mmio)
		iounmap(dev->mmio);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(dev);
}

static void i2c_wake_process(struct work_struct *p_work)
{
	struct tbs_i2c *i2c = container_of(p_work, struct tbs_i2c, i2cwork);
	i2c->ready =1;
	wake_up(&i2c->wq);
	return;
}

static void audio_wake_process(struct work_struct *p_work)
{
	struct tbs_audio *chip = container_of(p_work, struct tbs_audio, audiowork);
	snd_pcm_period_elapsed(chip->substream);
	return;
}

static void video_wake_process(struct work_struct *p_work)
{
	struct tbs_video *videodev = container_of(p_work, struct tbs_video, videowork);
	videodev->img_ready =1;
	wake_up(&videodev->wq);
	return;
}

static int ProcessStreamThread(void *data){
	struct vb2_queue *q =data;
	struct tbs_videofile_instance *stream= list_entry(q,struct tbs_videofile_instance,queue);
	struct tbs_video *videodev = q->drv_priv;

	void *					buf_mem;
	struct tbsvideo_buffer *buf;
    unsigned int iNum;
    unsigned int iNext1;
    unsigned int iNext2;
    unsigned int rwidth;
    unsigned int rheight;

	unsigned int dst_width=stream->select_width;
	unsigned int dst_height=stream->select_height;
	int timeout;

	//printk( "%s() index:%x \n", __func__, videodev->index);

	while( !kthread_should_stop() ){

		timeout = wait_event_timeout(videodev->wq, videodev->img_ready == 1, (HZ>>4));
		if (timeout <= 0) {
			msleep(1);
			continue;
		}
		videodev->img_ready=0;

		spin_lock(&stream->slock);
		if(list_empty(&stream->list)){
			spin_unlock(&stream->slock);
			msleep(1);
			continue;
		}

		buf = list_entry(stream->list.next, struct tbsvideo_buffer, queue);
		list_del(&buf->queue);	

		buf_mem = vb2_plane_vaddr(&buf->vb.vb2_buf,0);
		if(!buf_mem){
			buf->vb.vb2_buf.timestamp = ktime_get_ns();
			buf->vb.sequence = stream->seqnr++;
			buf->vb.field = V4L2_FIELD_NONE;
			vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
			spin_unlock(&stream->slock);			
			printk(KERN_INFO "%s() vb2_plane_vaddr NULL\n",__func__);
			continue;
		}

		rwidth = videodev->dst_width;
		rheight = videodev->dst_height;
		iNum = (videodev->videostatus) & 0x3;

		if(videodev->Interlaced){
			int i;
			iNext1 = (iNum + 1) % 3;
			iNext2 = (iNum + 2) % 3;
			for(i=0;i<rheight;i+=2){
				memcpy(stream->imgbuf0+(i+1)*rwidth*2,
					(u8*)videodev->dmabuf[iNext2].virtaddr+(i>>1)*rwidth*2,rwidth*2);
				memcpy(stream->imgbuf0+(i)*rwidth*2,
					(u8*)videodev->dmabuf[iNext1].virtaddr+(i>>1)*rwidth*2,rwidth*2);
			}
		}else{
			memcpy(stream->imgbuf0,(u8*)videodev->dmabuf[iNum].virtaddr,rwidth*rheight*2);
		}

		/* Protect FPU/SIMD registers */
		kernel_fpu_begin();

		if(stream->select_pixelformat == V4L2_PIX_FMT_UYVY){
			YUY2ToI422(stream->imgbuf0, rwidth << 1,
				stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth >> 1,
				stream->imgbuf1 + rwidth * rheight + (rwidth * rheight >> 1), rwidth >> 1,
				rwidth, rheight);
			I422Scale(stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth >> 1,
				stream->imgbuf1 + rwidth * rheight + (rwidth * rheight >> 1), rwidth >> 1,
				rwidth, rheight,
				stream->imgbuf0, dst_width,
				stream->imgbuf0 + dst_width * dst_height, dst_width >> 1,
				stream->imgbuf0 + dst_width * dst_height + (dst_width * dst_height >> 1), dst_width >> 1,
				dst_width, dst_height, 0
			);
			I422ToUYVY(stream->imgbuf0, dst_width,
						stream->imgbuf0 + dst_width * dst_height, dst_width >> 1,
						stream->imgbuf0 + dst_width * dst_height + (dst_width * dst_height >> 1), dst_width >> 1,
						buf_mem, dst_width << 1, dst_width, dst_height);

		}

		if(stream->select_pixelformat == V4L2_PIX_FMT_YUV420){ //YU12
			YUY2ToNV12(stream->imgbuf0, rwidth << 1,
				stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth,
				rwidth, rheight);

			NV12Scale(stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth,
				rwidth, rheight,
				stream->imgbuf0, dst_width,
				stream->imgbuf0 + dst_width * dst_height, dst_width,
				dst_width, dst_height, 0
			);
			NV12ToI420(stream->imgbuf0, dst_width, stream->imgbuf0 + dst_width * dst_height, dst_width,
				buf_mem, dst_width,
				buf_mem + dst_width * dst_height, dst_width >> 1,
				buf_mem + dst_width * dst_height + (dst_width * dst_height >> 2),dst_width >> 1,
				dst_width, dst_height);

		}

		if(stream->select_pixelformat == V4L2_PIX_FMT_YVU420){ //YV12
			YUY2ToNV12(stream->imgbuf0, rwidth << 1,
				stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth,
				rwidth, rheight);

			NV12Scale(stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth,
				rwidth, rheight,
				stream->imgbuf0, dst_width,
				stream->imgbuf0 + dst_width * dst_height, dst_width,
				dst_width, dst_height, 0
			);
			NV12ToI420(stream->imgbuf0, dst_width, stream->imgbuf0 + dst_width * dst_height, dst_width,
				buf_mem, dst_width,
				buf_mem + dst_width * dst_height + (dst_width * dst_height >> 2),dst_width >> 1,
				buf_mem + dst_width * dst_height, dst_width >> 1,
				dst_width, dst_height);

		}


		if(stream->select_pixelformat == V4L2_PIX_FMT_NV12){ //NV12
			YUY2ToNV12(stream->imgbuf0, rwidth << 1,
				stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth,
				rwidth, rheight);

			NV12Scale(stream->imgbuf1, rwidth,
				stream->imgbuf1 + rwidth * rheight, rwidth,
				rwidth, rheight,
				buf_mem, dst_width,
				buf_mem + dst_width * dst_height, dst_width,
				dst_width, dst_height, 0
			);
		}

		kernel_fpu_end();
		
		buf->vb.vb2_buf.timestamp = ktime_get_ns();
		buf->vb.sequence = stream->seqnr++;
		buf->vb.field = V4L2_FIELD_NONE;
		vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_DONE);
		spin_unlock(&stream->slock);

	}

	spin_lock(&stream->slock);
	while (!list_empty(&stream->list)) {
		struct tbsvideo_buffer *buf = list_entry(stream->list.next,
			struct tbsvideo_buffer, queue);
		list_del(&buf->queue);
		vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
	}
	spin_unlock(&stream->slock);

	return 0;
}


static int SignalDetectThread(void *data){
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev *)data;
	int status;
	unsigned long channelwidth[4];
	unsigned long channelheigh[4];
	unsigned long channelinterlaced[4];
	channelwidth[0] = channelwidth[1] =channelwidth[2] =channelwidth[3] =DEFAULT_WIDTH;
	channelheigh[0] = channelheigh[1] =channelheigh[2] =channelheigh[3] =DEFAULT_HEIGH;
	channelinterlaced[0] = channelinterlaced[1] =channelinterlaced[2] =channelinterlaced[3] =0;

	int i;
	//printk(KERN_INFO "%s() start\n",__func__);
	while (!kthread_should_stop())
	{
		for(i=0;i<INTERFACES;i++){		
			status = tbs_get_video_param(&dev->video[i]);
			if (status || dev->video[i].runstatus == 0) {
				stop_video_dma_transfer(&dev->video[i]);
				channelwidth[i] = dev->video[i].width = DEFAULT_WIDTH;
				channelheigh[i] = dev->video[i].height = DEFAULT_HEIGH;
				channelinterlaced[i] = dev->video[i].Interlaced = 0;
			}else {
				if (channelwidth[i] != dev->video[i].width ||
					channelheigh[i] != dev->video[i].height ||
					channelinterlaced[i] != dev->video[i].Interlaced) {

					//printk(KERN_INFO "%s() video %d switch\n", __func__,i);
					stop_video_dma_transfer(&dev->video[i]);
					msleep(50);
					start_video_dma_transfer(&dev->video[i]);
				}
				channelwidth[i] = dev->video[i].width;
				channelheigh[i] = dev->video[i].height;
				channelinterlaced[i] = dev->video[i].Interlaced;
			}
		}
//		msleep(1000);
		wait_event_timeout(dev->wq, dev->signal_ready == 1, HZ);
		dev->signal_ready=0;
	}
	//printk(KERN_INFO "%s() end\n",__func__);
	stop_video_dma_transfer(&dev->video[0]);
	stop_video_dma_transfer(&dev->video[1]);
	stop_video_dma_transfer(&dev->video[2]);
	stop_video_dma_transfer(&dev->video[3]);
	return 0;
}
static bool tbs_enable_msi(struct pci_dev *pdev, struct tbs_pcie_dev *dev)
{
	int err;

	if (!enable_msi) {
		dev_warn(&dev->pdev->dev,
			"MSI disabled by module parameter 'enable_msi'\n");
		return false;
	}

	err = pci_enable_msi(pdev);
	if (err) {
		dev_err(&dev->pdev->dev,
			"Failed to enable MSI interrupt."
			" Falling back to a shared IRQ\n");
		return false;
	}

	/* no error - so request an msi interrupt */
	err = request_irq(pdev->irq, tbs_pcie_irq, 0,
				KBUILD_MODNAME, dev);
	if (err) {
		/* fall back to legacy interrupt */
		dev_err(&dev->pdev->dev,
			"Failed to get an MSI interrupt."
			" Falling back to a shared IRQ\n");
		pci_disable_msi(pdev);
		return false;
	}
	return true;
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
		printk(KERN_ERR "pcie_tbs_probe ERROR: PCI enable failed %d\n", err);
		goto fail1;
	}

    if(!pdev->is_busmaster) {
        pdev->is_busmaster=1;
        pci_set_master(pdev);
    }
	
	dev->mmio = ioremap(pci_resource_start(dev->pdev, 0),
			pci_resource_len(dev->pdev, 0));
	if (!dev->mmio) {
		printk(KERN_ERR "pcie_tbs_probe ERROR: Mem 0 remap failed\n");
		ret = -ENODEV; /* -ENOMEM better?! */ 
		goto fail2;
	}

	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000000);

	//interrupts 
	if (tbs_enable_msi(pdev, dev)) {
		printk("KBUILD_MODNAME : %s --MSI!\n",KBUILD_MODNAME);
		dev->msi = true;
	} else {
		printk("KBUILD_MODNAME : %s --INTx\n\n",KBUILD_MODNAME);	
		ret = request_irq(dev->pdev->irq,tbs_pcie_irq,IRQF_SHARED,KBUILD_MODNAME,(void *) dev);
		if (ret != 0) {
			printk(KERN_ERR "pcie_tbs_probe ERROR: IRQ registration failed %d\n", ret);
			ret = -ENODEV;
			goto fail3;
		}
		dev->msi = false;
	}

	if (pdev->msix_enabled){
		printk("%s msix_enabled  irq:%d \n",__func__,pdev->irq);		
	}else if (pdev->msi_enabled){
		printk("%s msi_enabled  irq:%d \n",__func__,pdev->irq);		
	}else{
		printk("%s other  irq:%d \n",__func__,pdev->irq);	
	}
	
	pci_set_drvdata(pdev, dev);

	mutex_init(&(dev->devicemutex));

	init_waitqueue_head(&dev->wq);

	if (tbs_i2c_init(dev) < 0){
		printk(KERN_ERR "tbs_i2c_init failed \n");
		goto fail4;
	}

	tbs_adapters_init(dev);

	if( tbs_video_register(dev) ){
		printk(KERN_ERR "tbs_video_register failed \n");
		goto fail4;
	}

	if(tbs_audio_register(dev)){
		printk(KERN_ERR "tbs_audio_register failed \n");
		goto fail4;
	}

	dev->signalthread=kthread_run(SignalDetectThread,dev,"tbs_signalthread");
	printk("%s end\n",__func__);			
	return 0;

	printk("%s failed:%d end\n",__func__,ret);			
fail4:
	free_irq(dev->pdev->irq, dev);
fail3:
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

static int  tbs_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct tbs_pcie_dev *dev = 
		(struct tbs_pcie_dev*) pci_get_drvdata(pdev);
	//printk(KERN_INFO "%s() \n",__func__);
	mutex_lock(&dev->devicemutex);
	return 0;
}
	
static int  tbs_resume(struct pci_dev *pdev)
{
	struct tbs_pcie_dev *dev = 
		(struct tbs_pcie_dev*) pci_get_drvdata(pdev);

	//printk(KERN_INFO "%s() end\n",__func__);
	/* enable i2c interrupts */
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_0, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_1, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_2, 0x00000001);
	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_I2C_MASK_3, 0x00000001);

	tbs_adapters_init(dev);
	mutex_unlock(&dev->devicemutex);
	return 0;
}

#define MAKE_ENTRY( __vend, __chip, __subven, __subdev, __configptr) {	\
	.vendor		= (__vend),					\
	.device		= (__chip),					\
	.subvendor	= (__subven),					\
	.subdevice	= (__subdev),					\
	.driver_data	= (unsigned long) (__configptr)			\
}

static const struct pci_device_id tbs_pci_table[] = {
	MAKE_ENTRY(0x544d, 0x6178, 0x6314, 0x0003, NULL),
	{ }
};
MODULE_DEVICE_TABLE(pci, tbs_pci_table);

static struct pci_driver tbs_pci_driver = {
	.name        = KBUILD_MODNAME,
	.id_table    = tbs_pci_table,
	.probe       = tbs_probe,
	.remove      = tbs_remove,
	.suspend	 = tbs_suspend,
	.resume		 = tbs_resume,
};

static __init int pcie_tbs_init(void)
{
	wq = create_singlethread_workqueue("tbs");
	if (!wq)
		return -ENOMEM;

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

MODULE_DESCRIPTION("TBS PCIEx2 HDMI capture driver");
MODULE_AUTHOR("tbs");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
