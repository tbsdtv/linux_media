ccflags-y += -I$(srctree)/drivers/media/pci/tbscapture2/include
ccflags-y += -I$(srctree)/drivers/media/pci/tbscapture2/include/libyuv
ccflags-y += -I$(srctree)/include/linux

CFLAGS_X86 = -mhard-float -msse -msse2

CFLAGS_compare.o += $(CFLAGS_X86)
CFLAGS_compare_gcc.o += $(CFLAGS_X86)
CFLAGS_rotate_gcc.o += $(CFLAGS_X86)
CFLAGS_row_common.o += $(CFLAGS_X86)
CFLAGS_row_gcc.o += $(CFLAGS_X86)
CFLAGS_scale_gcc.o += $(CFLAGS_X86)
CFLAGS_planar_functions.o += $(CFLAGS_X86)

obj-$(CONFIG_TBS_PCIE2_CAP) += tbs_pcie2-cap.o
tbs_pcie2-cap-objs += tbs_pcie2.o \
other.o \
compare.o \
compare_common.o \
compare_gcc.o \
convert_from.o \
convert_from_argb.o \
convert_jpeg.o \
convert_to_argb.o \
convert.o \
convert_argb.o \
rotate_argb.o \
rotate_common.o \
rotate_gcc.o \
row_any.o \
row_common.o \
row_gcc.o \
mjpeg_validate.o \
planar_functions.o \
rotate.o \
rotate_any.o \
convert_to_i420.o \
cpu_id.o \
mjpeg_decoder.o \
scale.o \
scale_any.o \
scale_argb.o \
scale_common.o \
scale_gcc.o \
scale_rgb.o \
scale_uv.o \
video_common.o
