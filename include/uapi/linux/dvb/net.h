/* SPDX-License-Identifier: LGPL-2.1+ WITH Linux-syscall-note */
/*
 * net.h
 *
 * Copyright (C) 2000 Marcus Metzler <marcus@convergence.de>
 *                  & Ralph  Metzler <ralph@convergence.de>
 *                    for convergence integrated media GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef _DVBNET_H_
#define _DVBNET_H_

#include <linux/types.h>

#define NET_MULTICAST_MAX 10
#define DVB_NET_MAX_NO_OF_PID 16

typedef enum {
	MAC_ADDRESS_6_BYTES = 0,
	MAC_ADDRESS_3_BYTES,
} mac_type_t;

struct set_multi_pid_mac_entry {
	__u16 if_num;
	__u8 multi_pid_count;
	__u8 multi_mac_address[DVB_NET_MAX_NO_OF_PID][6];
	__u16 pid[DVB_NET_MAX_NO_OF_PID];
};

/**
 * struct dvb_net_if - describes a DVB network interface
 *
 * @pid: Packet ID (PID) of the MPEG-TS that contains data
 * @if_num: number of the Digital TV interface.
 * @feedtype: Encapsulation type of the feed.
 *
 * A MPEG-TS stream may contain packet IDs with IP packages on it.
 * This struct describes it, and the type of encoding.
 *
 * @feedtype can be:
 *
 *	- %DVB_NET_FEEDTYPE_MPE for MPE encoding
 *	- %DVB_NET_FEEDTYPE_ULE for ULE encoding.
  *	- %DVB_NET_FEEDTYPE_GSE for GSE encoding.
 */

#define DVB_NET_FEEDTYPE_MPE 0	/* multi protocol encapsulation */
#define DVB_NET_FEEDTYPE_ULE 1	/* ultra lightweight encapsulation */
#define DVB_NET_FEEDTYPE_GSE 2  /* generic stream  encapsulation */

struct dvb_net_if {
	__u16 pid;
	__u16 if_num;
	__u8  feedtype;
#ifdef DVBNET_MULTIPID_INFO
	struct set_multi_pid_mac_entry  multi_pid_table;
#endif
};


#define NET_ADD_IF    _IOWR('o', 52, struct dvb_net_if)
#define NET_REMOVE_IF _IO('o', 53)
#define NET_GET_IF    _IOWR('o', 54, struct dvb_net_if)


/* binary compatibility cruft: */
struct __dvb_net_if_old {
	__u16 pid;
	__u16 if_num;
};
#define __NET_ADD_IF_OLD _IOWR('o', 52, struct __dvb_net_if_old)
#define __NET_GET_IF_OLD _IOWR('o', 54, struct __dvb_net_if_old)

struct set_unicast_mac_address {
	mac_type_t mac_type;
	union{
		__u8 mac_address[6];
		__u8 short_mac_address[3];
	};
};

struct set_multicast_mac_address {
	__u8 multi_mac_count;
	__u8 multi_mac_address[NET_MULTICAST_MAX][6];
	_Bool set_short_mac;
        __u8 short_mac_address[3]; /*As per Protocol GSE support simultaneous use of several 6-byte and one 3-byte addresses */
};



#define NET_SET_UNICAST_MAC_IF    _IOWR('o', 55, struct set_unicast_mac_address)
#define NET_SET_MULTICAST_MAC_IF    _IOWR('o', 56, struct set_multicast_mac_address)
#define NET_SET_MULTI_PID_MAC_IF    _IOWR('o', 57, struct set_multi_pid_mac_entry)


#endif /*_DVBNET_H_*/
