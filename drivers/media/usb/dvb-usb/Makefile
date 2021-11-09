# SPDX-License-Identifier: GPL-2.0
dvb-usb-objs += dvb-usb-firmware.o dvb-usb-init.o dvb-usb-urb.o dvb-usb-i2c.o
dvb-usb-objs += dvb-usb-dvb.o dvb-usb-remote.o usb-urb.o
obj-$(CONFIG_DVB_USB) += dvb-usb.o

dvb-usb-vp7045-objs := vp7045.o vp7045-fe.o
obj-$(CONFIG_DVB_USB_VP7045) += dvb-usb-vp7045.o

dvb-usb-vp702x-objs := vp702x.o vp702x-fe.o
obj-$(CONFIG_DVB_USB_VP702X) += dvb-usb-vp702x.o

dvb-usb-gp8psk-objs := gp8psk.o
obj-$(CONFIG_DVB_USB_GP8PSK) += dvb-usb-gp8psk.o

dvb-usb-dtt200u-objs := dtt200u.o dtt200u-fe.o
obj-$(CONFIG_DVB_USB_DTT200U) += dvb-usb-dtt200u.o

dvb-usb-dibusb-common-objs := dibusb-common.o

dvb-usb-dibusb-mc-common-objs := dibusb-mc-common.o
obj-$(CONFIG_DVB_USB_DIB3000MC)	+= dvb-usb-dibusb-common.o dvb-usb-dibusb-mc-common.o

dvb-usb-a800-objs := a800.o
obj-$(CONFIG_DVB_USB_A800) += dvb-usb-a800.o

dvb-usb-dibusb-mb-objs := dibusb-mb.o
obj-$(CONFIG_DVB_USB_DIBUSB_MB) += dvb-usb-dibusb-common.o dvb-usb-dibusb-mb.o

dvb-usb-dibusb-mc-objs := dibusb-mc.o
obj-$(CONFIG_DVB_USB_DIBUSB_MC) += dvb-usb-dibusb-mc.o

dvb-usb-nova-t-usb2-objs := nova-t-usb2.o
obj-$(CONFIG_DVB_USB_NOVA_T_USB2) += dvb-usb-nova-t-usb2.o

dvb-usb-umt-010-objs := umt-010.o
obj-$(CONFIG_DVB_USB_UMT_010) += dvb-usb-umt-010.o

dvb-usb-m920x-objs := m920x.o
obj-$(CONFIG_DVB_USB_M920X) += dvb-usb-m920x.o

dvb-usb-digitv-objs := digitv.o
obj-$(CONFIG_DVB_USB_DIGITV) += dvb-usb-digitv.o

dvb-usb-cxusb-objs := cxusb.o
ifeq ($(CONFIG_DVB_USB_CXUSB_ANALOG),y)
dvb-usb-cxusb-objs += cxusb-analog.o
endif
obj-$(CONFIG_DVB_USB_CXUSB) += dvb-usb-cxusb.o

dvb-usb-ttusb2-objs := ttusb2.o
obj-$(CONFIG_DVB_USB_TTUSB2) += dvb-usb-ttusb2.o

dvb-usb-dib0700-objs := dib0700_core.o dib0700_devices.o
obj-$(CONFIG_DVB_USB_DIB0700) += dvb-usb-dib0700.o

dvb-usb-opera-objs := opera1.o
obj-$(CONFIG_DVB_USB_OPERA1) += dvb-usb-opera.o

dvb-usb-af9005-objs := af9005.o af9005-fe.o
obj-$(CONFIG_DVB_USB_AF9005) += dvb-usb-af9005.o

dvb-usb-af9005-remote-objs := af9005-remote.o
obj-$(CONFIG_DVB_USB_AF9005_REMOTE) += dvb-usb-af9005-remote.o

dvb-usb-pctv452e-objs := pctv452e.o
obj-$(CONFIG_DVB_USB_PCTV452E) += dvb-usb-pctv452e.o

dvb-usb-dw2102-objs := dw2102.o
obj-$(CONFIG_DVB_USB_DW2102) += dvb-usb-dw2102.o

dvb-usb-dtv5100-objs := dtv5100.o
obj-$(CONFIG_DVB_USB_DTV5100) += dvb-usb-dtv5100.o

dvb-usb-cinergyT2-objs := cinergyT2-core.o cinergyT2-fe.o
obj-$(CONFIG_DVB_USB_CINERGY_T2) += dvb-usb-cinergyT2.o

dvb-usb-az6027-objs := az6027.o
obj-$(CONFIG_DVB_USB_AZ6027) += dvb-usb-az6027.o

dvb-usb-technisat-usb2-objs := technisat-usb2.o
obj-$(CONFIG_DVB_USB_TECHNISAT_USB2) += dvb-usb-technisat-usb2.o

dvb-usb-tbsqbox-objs = tbs-qbox.o
obj-$(CONFIG_DVB_USB_TBSQBOX) += dvb-usb-tbsqbox.o

dvb-usb-tbsqbox2-objs = tbs-qbox2.o
obj-$(CONFIG_DVB_USB_TBSQBOX2) += dvb-usb-tbsqbox2.o

dvb-usb-tbsqbox22-objs = tbs-qbox22.o
obj-$(CONFIG_DVB_USB_TBSQBOX22) += dvb-usb-tbsqbox22.o

dvb-usb-tbs5922se-objs = tbs5922se.o
obj-$(CONFIG_DVB_USB_TBS5922SE) += dvb-usb-tbs5922se.o

dvb-usb-tbsqboxs2-objs = tbs-qboxs2.o
obj-$(CONFIG_DVB_USB_TBSQBOXS2) += dvb-usb-tbsqboxs2.o

dvb-usb-tbsqbox2ci-objs = tbs-qbox2ci.o
obj-$(CONFIG_DVB_USB_TBSQBOX2CI) += dvb-usb-tbsqbox2ci.o

dvb-usb-tbs5925-objs = tbs5925.o
obj-$(CONFIG_DVB_USB_TBS5925) += dvb-usb-tbs5925.o

dvb-usb-tbs5880-objs = tbs5880.o
obj-$(CONFIG_DVB_USB_TBS5880) += dvb-usb-tbs5880.o

dvb-usb-tbs5220-objs = tbs5220.o
obj-$(CONFIG_DVB_USB_TBS5220) += dvb-usb-tbs5220.o

dvb-usb-tbs5881-objs = tbs5881.o
obj-$(CONFIG_DVB_USB_TBS5881) += dvb-usb-tbs5881.o

dvb-usb-tbs5520-objs := tbs5520.o
obj-$(CONFIG_DVB_USB_TBS5520) += dvb-usb-tbs5520.o

dvb-usb-tbs5520se-objs = tbs5520se.o
obj-$(CONFIG_DVB_USB_TBS5520se) += dvb-usb-tbs5520se.o

dvb-usb-tbs5580-objs = tbs5580.o
obj-$(CONFIG_DVB_USB_TBS5580) += dvb-usb-tbs5580.o

dvb-usb-tbs5927-objs = tbs5927.o
obj-$(CONFIG_DVB_USB_TBS5927) += dvb-usb-tbs5927.o

dvb-usb-tbs5301-objs = tbs5301.o
obj-$(CONFIG_DVB_USB_TBS5301) += dvb-usb-tbs5301.o

dvb-usb-tbs5930-objs = tbs5930.o
obj-$(CONFIG_DVB_USB_TBS5930) += dvb-usb-tbs5930.o

dvb-usb-tbs5590-objs = tbs5590.o
obj-$(CONFIG_DVB_USB_TBS5590) += dvb-usb-tbs5590.o

ccflags-y += -I$(srctree)/drivers/media/dvb-frontends/
# due to tuner-xc3028
ccflags-y += -I$(srctree)/drivers/media/tuners
ccflags-y += -I$(srctree)/drivers/media/common
