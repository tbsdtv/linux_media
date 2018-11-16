/*
 * dvb_demux.h: DVB kernel demux API
 *
 * Copyright (C) 2000-2001 Marcus Metzler & Ralph Metzler
 *                         for convergence integrated media GmbH
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
 */

#ifndef _DVB_DEMUX_H_
#define _DVB_DEMUX_H_

#include <linux/time.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

#include <media/demux.h>

#define MAX_NUMBER_OF_PID		16

/**
 * enum dvb_dmx_filter_type - type of demux feed.
 *
 * @DMX_TYPE_TS:	feed is in TS mode.
 * @DMX_TYPE_SEC:	feed is in Section mode.
 */
enum dvb_dmx_filter_type {
	DMX_TYPE_TS,
	DMX_TYPE_SEC,
	DMX_TYPE_PES,
	DMX_TYPE_GSE,
	DMX_TYPE_IP_SEC,
};

/**
 * enum dvb_dmx_state - state machine for a demux filter.
 *
 * @DMX_STATE_FREE:		indicates that the filter is freed.
 * @DMX_STATE_ALLOCATED:	indicates that the filter was allocated
 *				to be used.
 * @DMX_STATE_READY:		indicates that the filter is ready
 *				to be used.
 * @DMX_STATE_GO:		indicates that the filter is running.
 */
enum dvb_dmx_state {
	DMX_STATE_FREE,
	DMX_STATE_ALLOCATED,
	DMX_STATE_READY,
	DMX_STATE_GO,
};

#define DVB_DEMUX_MASK_MAX 18

#define MAX_PID 0x1fff

#define SPEED_PKTS_INTERVAL 50000

#define GSE_FULL_PDU_HEADER_LENGTH 4
#define GSE_FIRST_FRAG_HEADER_LENGTH 7
#define GSE_END_BIT_MANUALY_SET  (0x1 << 6)
#define GSE_TOTAL_LENGTH_OFFSET 3
#define GSE_MAX_FRAGMENT_COUNT 0xffff
#define GSE_PACKET_MAX_TIMEOUT  0xffffffff /*TODO*/

#define GSE_STATUS_OK   0x00000000
/**< Minimum length of a GSE packet (in Bytes)  1Byte fragid + 1Byte pdu + 2Byte min header*/
#define GSE_MIN_PACKET_LENGTH 4
/* Maximum GSE packet length = GSE length  4095 + Minimum 2 Bytes header. */
#define GSE_MAX_PACKET_LENGTH 4097
/**< Minimum value for EtherTypes */
#define GSE_MIN_ETHER_TYPE 1536
/**< Length of the mandatory fields (in Bytes) (E, S, LT, GSE_Length) */
#define GSE_MANDATORY_FIELDS_LENGTH 2
/**< Length of Frag ID field (in Bytes) */
#define GSE_FRAG_ID_LENGTH 1
/**< Length of Total length field (in Bytes) */
#define GSE_TOTAL_LENGTH_LENGTH 2
/**< Length of Protocol type field (in Bytes) */
#define GSE_PROTOCOL_TYPE_LENGTH 2
/* Maximum length of a GSE header (in Bytes) */
#define GSE_MAX_HEADER_LENGTH 13
/* Maximum length of a GSE trailer (in Bytes) (length of CRC32) */
#define GSE_MAX_TRAILER_LENGTH 4
/* Maximum offset between a fragmented PDU and a refragmented one */
#define GSE_MAX_REFRAG_HEAD_OFFSET 3
/* Max supported PDU Frag ID */
#define MAX_PDU_FRAGMENT_ID             255
/* Maximum length of a PDU (in Bytes) */
#define GSE_MAX_PDU_LENGTH 65535
/* GSE 6 Bytes label */
#define GSE_6_BYTES_LABEL       6
/* GSE 3 Bytes label */
#define GSE_3_BYTES_LABEL       3

/* Special ID has been defined to manage full PDU packet
*  Warning: It is reserved for full PDU. It should not be used
*  any other purpose */
#define FULL_PDU_PACKET_ID      256
#define GSE_LABEL_BITS          0x30

/* Pass first 4 bytes.Then, shift 30 bits to extract payload type */
#define GSE_PAYLOAD_TYPE(four_bytes)    (four_bytes >> 30)
/* Pass first 4 bytes.Then, shift 28 bits to extract label type */
#define GSE_LABEL_TYPE(four_bytes)      ((four_bytes & 0x30000000)>> 28)

/**< Initial value for CRC32 computation */
#define GSE_CRC_INIT 0xFFFFFFFF

typedef enum {
	/* Indicates that a 6 bytes label is present and  shall
	 * be used for filtering. (e.g., a IEEE MAC address) */
	GSE_PKT_LABEL_SIX_BYTES = 0,
	/* Indicates that a 3 bytes label is present and shall
	 * be used for filtering. (e.g., a RCS group/logon ID) */
	GSE_PKT_LABEL_THREE_BYTES = 1,
	/*No label present. All receivers shall process this packet */
	GSE_PKT_LABEL_NONE = 2,
	/* label is the same as the previous GSE packet
	 * in the same base band frame */
	GSE_PKT_LABEL_REUSE = 3,
}gse_label_type_t;

#if 0
typedef enum {
        GSE_LT_6_BYTES  = 0,   /**< 6-bytes label '00' */
        GSE_LT_3_BYTES  ,   /**< 3-bytes label '01' */
        GSE_LT_NO_LABELS ,   /**< No label '10' */
        GSE_LT_REUSE       /**< label re-use or reserved value for PDU subsequent fragments '11' */
}gse_label_type_t;
#endif

/** Type of payload carried by the GSE packet */
enum gse_payload_type {
  GSE_NEXT_FRAG_PDU = 0,   /**< Subsequent fragment of PDU which is not the last one */
  GSE_LAST_FRAG_PDU,   /**< Last fragment of PDU */
  GSE_FIRST_FRAG_PDU,  /**< First fragment of PDU */
  GSE_FULL_PDU    /**< Complete PDU */
};

/**
 * struct dvb_demux_filter - Describes a DVB demux section filter.
 *
 * @filter:		Section filter as defined by &struct dmx_section_filter.
 * @maskandmode:	logical ``and`` bit mask.
 * @maskandnotmode:	logical ``and not`` bit mask.
 * @doneq:		flag that indicates when a filter is ready.
 * @next:		pointer to the next section filter.
 * @feed:		&struct dvb_demux_feed pointer.
 * @index:		index of the used demux filter.
 * @state:		state of the filter as described by &enum dvb_dmx_state.
 * @type:		type of the filter as described
 *			by &enum dvb_dmx_filter_type.
 */

struct dvb_demux_filter {
	struct dmx_section_filter filter;
	struct dmx_ip_section_filter ip_filter;
	struct dmx_gsesection_filter gsefilter;
	struct dmx_gselabel_filter gselabelfilter;
	u8 maskandmode[DMX_MAX_FILTER_SIZE];
	u8 maskandnotmode[DMX_MAX_FILTER_SIZE];
	bool doneq;

	struct dvb_demux_filter *next;
	struct dvb_demux_feed *feed;
	int index;
	enum dvb_dmx_state state;
	enum dvb_dmx_filter_type type;

	/* private: used only by av7110 */
	u16 hw_handle;
};

/* gse demux_feed */
struct dvb_demux_gse {
	/* Feed type (GSE_SI, GSE_PDU_CONT or GSE_PDU) */
	u8 type;
	/* Payload only or full Gse Packet */
	u8 gse_payload_type;
	u16 protocol_type;
};

/**
 * struct dvb_demux_feed - describes a DVB field
 *
 * @feed:	a union describing a digital TV feed.
 *		Depending on the feed type, it can be either
 *		@feed.ts or @feed.sec.
 * @feed.ts:	a &struct dmx_ts_feed pointer.
 *		For TS feed only.
 * @feed.sec:	a &struct dmx_section_feed pointer.
 *		For section feed only.
 * @cb:		a union describing digital TV callbacks.
 *		Depending on the feed type, it can be either
 *		@cb.ts or @cb.sec.
 * @cb.ts:	a dmx_ts_cb() calback function pointer.
 *		For TS feed only.
 * @cb.sec:	a dmx_section_cb() callback function pointer.
 *		For section feed only.
 * @demux:	pointer to &struct dvb_demux.
 * @priv:	private data that can optionally be used by a DVB driver.
 * @type:	type of the filter, as defined by &enum dvb_dmx_filter_type.
 * @state:	state of the filter as defined by &enum dvb_dmx_state.
 * @pid:	PID to be filtered.
 * @timeout:	feed timeout.
 * @filter:	pointer to &struct dvb_demux_filter.
 * @buffer_flags: Buffer flags used to report discontinuity users via DVB
 *		  memory mapped API, as defined by &enum dmx_buffer_flags.
 * @ts_type:	type of TS, as defined by &enum ts_filter_type.
 * @pes_type:	type of PES, as defined by &enum dmx_ts_pes.
 * @cc:		MPEG-TS packet continuity counter
 * @pusi_seen:	if true, indicates that a discontinuity was detected.
 *		it is used to prevent feeding of garbage from previous section.
 * @peslen:	length of the PES (Packet Elementary Stream).
 * @list_head:	head for the list of digital TV demux feeds.
 * @index:	a unique index for each feed. Can be used as hardware
 *		pid filter index.
 */
struct dvb_demux_feed {
	union {
		struct dmx_ts_feed ts;
		struct dmx_section_feed sec;
		struct dmx_gse_feed gse;
		struct dmx_ip_section_feed ip_sec;
	} feed;

	union {
		dmx_ts_cb ts;
		dmx_section_cb sec;
		dmx_ip_section_cb ip_sec;
		dmx_gse_cb gse;
		dmx_gse_section_cb gse_sec;
	} cb;

	struct dvb_demux *demux;
	void *priv;
	enum dvb_dmx_filter_type type;
	enum dvb_dmx_state state;
	u16 pid;
	u16 ip_pid[MAX_NUMBER_OF_PID];
	u16 ip_new_pid[MAX_NUMBER_OF_PID];

	u8 ip_pid_index;
	struct {
		u8  pcr[6];
		u8	tagtm[6];
	} time_info;

	ktime_t timeout;
	struct dvb_demux_filter *filter;

	u32 buffer_flags;

	enum ts_filter_type ts_type;
	enum dmx_ts_pes pes_type;

	struct dvb_demux_gse gse;
	int cc[MAX_NUMBER_OF_PID];
	bool pusi_seen[MAX_NUMBER_OF_PID];		/* prevents feeding of garbage from previous section */

	u16 peslen;

	struct list_head list_head;
	unsigned int index;
};

struct gse_buff {
        unsigned char   *data;
        unsigned int    len;
	unsigned int    frag_id;
        ktime_t         tstamp;
	struct list_head list_head;
};

struct demux_gse {
	struct gse_buff *gse_full_pdu;       /* GSE for full pdu case SNDU decodes into this buffer. */
	struct gse_buff *gse_frag_pdu[MAX_PDU_FRAGMENT_ID];/* GSE for partiall pdu SNDU decodes into this buffer. */
	u8 gse_frag_pdu_count[MAX_PDU_FRAGMENT_ID];  /* fragmented  pdu count */
	u8 gse_label_len;
	u8 gse_label[6];
	u8 active_gse_buff_count;
};

/**
 * struct dvb_demux - represents a digital TV demux
 * @dmx:		embedded &struct dmx_demux with demux capabilities
 *			and callbacks.
 * @priv:		private data that can optionally be used by
 *			a DVB driver.
 * @filternum:		maximum amount of DVB filters.
 * @feednum:		maximum amount of DVB feeds.
 * @start_feed:		callback routine to be called in order to start
 *			a DVB feed.
 * @stop_feed:		callback routine to be called in order to stop
 *			a DVB feed.
 * @write_to_decoder:	callback routine to be called if the feed is TS and
 *			it is routed to an A/V decoder, when a new TS packet
 *			is received.
 *			Used only on av7110-av.c.
 * @check_crc32:	callback routine to check CRC. If not initialized,
 *			dvb_demux will use an internal one.
 * @memcopy:		callback routine to memcopy received data.
 *			If not initialized, dvb_demux will default to memcpy().
 * @users:		counter for the number of demux opened file descriptors.
 *			Currently, it is limited to 10 users.
 * @filter:		pointer to &struct dvb_demux_filter.
 * @feed:		pointer to &struct dvb_demux_feed.
 * @frontend_list:	&struct list_head with frontends used by the demux.
 * @pesfilter:		array of &struct dvb_demux_feed with the PES types
 *			that will be filtered.
 * @pids:		list of filtered program IDs.
 * @feed_list:		&struct list_head with feeds.
 * @tsbuf:		temporary buffer used internally to store TS packets.
 * @tsbufp:		temporary buffer index used internally.
 * @mutex:		pointer to &struct mutex used to protect feed set
 *			logic.
 * @lock:		pointer to &spinlock_t, used to protect buffer handling.
 * @cnt_storage:	buffer used for TS/TEI continuity check.
 * @speed_last_time:	&ktime_t used for TS speed check.
 * @speed_pkts_cnt:	packets count used for TS speed check.
 */
struct dvb_demux {
	struct dmx_demux dmx;
	void *priv;
	int filternum;
	int feednum;
	int (*start_feed)(struct dvb_demux_feed *feed);
	int (*stop_feed)(struct dvb_demux_feed *feed);
	int (*write_to_decoder)(struct dvb_demux_feed *feed,
				 const u8 *buf, size_t len);
	u32 (*check_crc32)(struct dvb_demux_feed *feed,
			    const u8 *buf, size_t len);
	void (*memcopy)(struct dvb_demux_feed *feed, u8 *dst,
			 const u8 *src, size_t len);

	int users;
#define MAX_DVB_DEMUX_USERS 10
	struct dvb_demux_filter *filter;
	struct dvb_demux_feed *feed;

	struct list_head frontend_list;

	struct dvb_demux_feed *pesfilter[DMX_PES_OTHER];
	u16 pids[DMX_PES_OTHER];

#define DMX_MAX_PID 0x2000
	struct list_head feed_list;
	u8 tsbuf[204];
	int tsbufp;

	/* Members which are specific to the GSE-Demux */
	struct demux_gse gse;
	struct list_head gse_buff_list;

	struct mutex mutex;
	spinlock_t lock;

	uint8_t *cnt_storage; /* for TS continuity check */

	ktime_t speed_last_time; /* for TS speed check */
	uint32_t speed_pkts_cnt; /* for TS speed check */

	/* private: used only on av7110 */
	int playing;
	int recording;
};

/**
 * dvb_dmx_init - initialize a digital TV demux struct.
 *
 * @demux: &struct dvb_demux to be initialized.
 *
 * Before being able to register a digital TV demux struct, drivers
 * should call this routine. On its typical usage, some fields should
 * be initialized at the driver before calling it.
 *
 * A typical usecase is::
 *
 *	dvb->demux.dmx.capabilities =
 *		DMX_TS_FILTERING | DMX_SECTION_FILTERING |
 *		DMX_MEMORY_BASED_FILTERING;
 *	dvb->demux.priv       = dvb;
 *	dvb->demux.filternum  = 256;
 *	dvb->demux.feednum    = 256;
 *	dvb->demux.start_feed = driver_start_feed;
 *	dvb->demux.stop_feed  = driver_stop_feed;
 *	ret = dvb_dmx_init(&dvb->demux);
 *	if (ret < 0)
 *		return ret;
 */
int dvb_dmx_init(struct dvb_demux *demux);

/**
 * dvb_dmx_release - releases a digital TV demux internal buffers.
 *
 * @demux: &struct dvb_demux to be released.
 *
 * The DVB core internally allocates data at @demux. This routine
 * releases those data. Please notice that the struct itelf is not
 * released, as it can be embedded on other structs.
 */
void dvb_dmx_release(struct dvb_demux *demux);

/**
 * dvb_dmx_swfilter_packets - use dvb software filter for a buffer with
 *	multiple MPEG-TS packets with 188 bytes each.
 *
 * @demux: pointer to &struct dvb_demux
 * @buf: buffer with data to be filtered
 * @count: number of MPEG-TS packets with size of 188.
 *
 * The routine will discard a DVB packet that don't start with 0x47.
 *
 * Use this routine if the DVB demux fills MPEG-TS buffers that are
 * already aligned.
 *
 * NOTE: The @buf size should have size equal to ``count * 188``.
 */
void dvb_dmx_swfilter_packets(struct dvb_demux *demux, const u8 *buf,
			      size_t count);

/**
 * dvb_dmx_swfilter -  use dvb software filter for a buffer with
 *	multiple MPEG-TS packets with 188 bytes each.
 *
 * @demux: pointer to &struct dvb_demux
 * @buf: buffer with data to be filtered
 * @count: number of MPEG-TS packets with size of 188.
 *
 * If a DVB packet doesn't start with 0x47, it will seek for the first
 * byte that starts with 0x47.
 *
 * Use this routine if the DVB demux fill buffers that may not start with
 * a packet start mark (0x47).
 *
 * NOTE: The @buf size should have size equal to ``count * 188``.
 */
void dvb_dmx_swfilter(struct dvb_demux *demux, const u8 *buf, size_t count);

/**
 * dvb_dmx_swfilter_204 -  use dvb software filter for a buffer with
 *	multiple MPEG-TS packets with 204 bytes each.
 *
 * @demux: pointer to &struct dvb_demux
 * @buf: buffer with data to be filtered
 * @count: number of MPEG-TS packets with size of 204.
 *
 * If a DVB packet doesn't start with 0x47, it will seek for the first
 * byte that starts with 0x47.
 *
 * Use this routine if the DVB demux fill buffers that may not start with
 * a packet start mark (0x47).
 *
 * NOTE: The @buf size should have size equal to ``count * 204``.
 */
void dvb_dmx_swfilter_204(struct dvb_demux *demux, const u8 *buf,
			  size_t count);

/**
 * dvb_dmx_swfilter_raw -  make the raw data available to userspace without
 *	filtering
 *
 * @demux: pointer to &struct dvb_demux
 * @buf: buffer with data
 * @count: number of packets to be passed. The actual size of each packet
 *	depends on the &dvb_demux->feed->cb.ts logic.
 *
 * Use it if the driver needs to deliver the raw payload to userspace without
 * passing through the kernel demux. That is meant to support some
 * delivery systems that aren't based on MPEG-TS.
 *
 * This function relies on &dvb_demux->feed->cb.ts to actually handle the
 * buffer.
 */
void dvb_dmx_swfilter_raw(struct dvb_demux *demux, const u8 *buf,
			  size_t count);

/* Pass a single gse packet to  demultiplexer
 * param demux Pointer to DVB demux context
 * param frame Buffer containing the gse packet
 * param len Length of the gse packet
 * note This function MUST NOT be call from inside a feed callback
 */
void dvb_dmx_swfilter_gse(struct dvb_demux *demux, const u8 *frame, size_t len);

#endif /* _DVB_DEMUX_H_ */
