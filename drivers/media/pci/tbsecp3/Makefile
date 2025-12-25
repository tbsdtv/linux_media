
tbsecp3-objs	:= tbsecp3-core.o tbsecp3-cards.o tbsecp3-i2c.o tbsecp3-dma.o tbsecp3-dvb.o tbsecp3-ca.o tbsecp3-asi.o tbsecp3-ci.o

obj-$(CONFIG_DVB_TBSECP3) += tbsecp3.o

ccflags-y += -Idrivers/media/tuners
ccflags-y += -Idrivers/media/dvb-core
ccflags-y += -Idrivers/media/dvb-frontends
ccflags-y += -Idrivers/media/dvb-frontends/stid135
