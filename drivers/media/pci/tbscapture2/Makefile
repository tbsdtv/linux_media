#EXTRA_CFLAGS += -I drivers/media/dvb-core
#EXTRA_CFLAGS +=  -I drivers/media/pci/tbscapture/include
#EXTRA_CFLAGS += -I /lib/modules/`uname -r`/build/include
#EXTRA_CFLAGS += -I /lib/modules/`uname -r`/build/include/linux

ccflags-y += -I$(srctree)/drivers/media/pci/tbscapture2/include
ccflags-y += -I$(srctree)/drivers/media/pci/tbscapture2/include/libyuv
ccflags-y += -I$(srctree)/include/linux

EXTRA_CFLAGS += -mhard-float -msse -msse2

#CC_FLAGS_FPU := -mhard-float -msse -msse2
obj-$(CONFIG_TBS_PCIE2_CAP) += tbs_pcie2-cap.o
tbs_pcie2-cap-objs += tbs_pcie2.o \
other.o \
compare.o \
compare_common.o \
compare_gcc.o \
compare_msa.o \
compare_neon.o \
compare_neon64.o \
convert_from.o \
convert_from_argb.o \
convert_jpeg.o \
convert_to_argb.o \
compare_win.o \
convert.o \
convert_argb.o \
rotate_argb.o \
rotate_common.o \
rotate_gcc.o \
rotate_lsx.o \
rotate_msa.o \
rotate_neon.o \
rotate_neon64.o \
rotate_sme.o \
rotate_win.o \
row_any.o \
row_common.o \
row_gcc.o \
row_lasx.o \
row_lsx.o \
mjpeg_validate.o \
planar_functions.o \
rotate.o \
rotate_any.o \
convert_to_i420.o \
cpu_id.o \
mjpeg_decoder.o \
row_msa.o \
row_neon.o \
row_neon64.o \
row_rvv.o \
row_sve.o \
row_win.o \
scale.o \
scale_any.o \
scale_argb.o \
scale_common.o \
scale_gcc.o \
scale_lsx.o \
scale_msa.o \
scale_neon.o \
scale_neon64.o \
scale_rgb.o \
scale_rvv.o \
scale_uv.o \
scale_win.o \
video_common.o
