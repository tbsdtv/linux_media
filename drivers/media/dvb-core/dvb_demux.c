// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * dvb_demux.c - DVB kernel demux API
 *
 * Copyright (C) 2000-2001 Ralph  Metzler <ralph@convergence.de>
 *		       & Marcus Metzler <marcus@convergence.de>
 *			 for convergence integrated media GmbH
 */

#define pr_fmt(fmt) "dvb_demux: " fmt

#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/crc32.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <asm/div64.h>

#include <media/dvb_demux.h>

static int dvb_demux_tscheck;
module_param(dvb_demux_tscheck, int, 0644);
MODULE_PARM_DESC(dvb_demux_tscheck,
		"enable transport stream continuity and TEI check");

static int dvb_demux_speedcheck;
module_param(dvb_demux_speedcheck, int, 0644);
MODULE_PARM_DESC(dvb_demux_speedcheck,
		"enable transport stream speed check");

static int dvb_demux_feed_err_pkts = 1;
module_param(dvb_demux_feed_err_pkts, int, 0644);
MODULE_PARM_DESC(dvb_demux_feed_err_pkts,
		 "when set to 0, drop packets with the TEI bit set (1 by default)");

static int dvb_demux_gsecheck;
module_param(dvb_demux_gsecheck, int, 0644);
MODULE_PARM_DESC(dvb_demux_gsecheck,
		"enable GSE check");

#define dprintk(fmt, arg...) \
	printk(KERN_DEBUG pr_fmt("%s: " fmt),  __func__, ##arg)

#define dprintk_tscheck(x...) do {			\
	if (dvb_demux_tscheck && printk_ratelimit())	\
		dprintk(x);				\
} while (0)

#define dprintk_gsecheck(x...) do {			\
	if (dvb_demux_gsecheck && printk_ratelimit())	\
		dprintk(x);				\
} while (0)

#ifdef CONFIG_DVB_DEMUX_SECTION_LOSS_LOG
#  define dprintk_sect_loss(x...) dprintk(x)
#else
#  define dprintk_sect_loss(x...)
#endif

#define set_buf_flags(__feed, __flag)			\
	do {						\
		(__feed)->buffer_flags |= (__flag);	\
	} while (0)

/******************************************************************************
 * static inlined helper functions
 ******************************************************************************/

static inline u16 section_length(const u8 *buf)
{
	return 3 + ((buf[1] & 0x0f) << 8) + buf[2];
}

static inline u16 ts_pid(const u8 *buf)
{
	return ((buf[1] & 0x1f) << 8) + buf[2];
}

static inline u8 payload(const u8 *tsp)
{
	if (!(tsp[3] & 0x10))	// no payload?
		return 0;

	if (tsp[3] & 0x20) {	// adaptation field?
		if (tsp[4] > 183)	// corrupted data?
			return 0;
		else
			return 184 - 1 - tsp[4];
	}

	return 184;
}

static u32 dvb_dmx_crc32(struct dvb_demux_feed *f, const u8 *src, size_t len)
{
	return (f->feed.sec.crc_val = crc32_be(f->feed.sec.crc_val, src, len));
}

static u32 dvb_dmx_ip_crc32(struct dvb_demux_feed *f, const u8 *src, size_t len,
		u8 index)
{
	return (f->feed.ip_sec.crc_val[index] =
			crc32_be(f->feed.ip_sec.crc_val[index], src, len));
}

static void dvb_dmx_memcopy(struct dvb_demux_feed *f, u8 *d, const u8 *s,
			    size_t len)
{
	memcpy(d, s, len);
}

/******************************************************************************
 * Software filter functions
 ******************************************************************************/

static inline int dvb_dmx_swfilter_payload(struct dvb_demux_feed *feed,
					   const u8 *buf)
{
	int count = payload(buf);
	int p;
	int ccok;
	u8 cc;

	if (count == 0)
		return -1;

	p = 188 - count;

	cc = buf[3] & 0x0f;
	ccok = ((feed->cc[0] + 1) & 0x0f) == cc;
	feed->cc[0] = cc;
	if (!ccok) {
		set_buf_flags(feed, DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED);
		dprintk_sect_loss("missed packet: %d instead of %d!\n",
				  cc, (feed->cc[0] + 1) & 0x0f);
	}

	if (buf[1] & 0x40)	// PUSI ?
		feed->peslen = 0xfffa;

	feed->peslen += count;

	return feed->cb.ts(&buf[p], count, NULL, 0, &feed->feed.ts,
			   &feed->buffer_flags);
}

static int dvb_dmx_swfilter_sectionfilter(struct dvb_demux_feed *feed,
					  struct dvb_demux_filter *f)
{
	u8 neq = 0;
	int i;

	for (i = 0; i < DVB_DEMUX_MASK_MAX; i++) {
		u8 xor = f->filter.filter_value[i] ^ feed->feed.sec.secbuf[i];

		if (f->maskandmode[i] & xor)
			return 0;

		neq |= f->maskandnotmode[i] & xor;
	}

	if (f->doneq && !neq)
		return 0;

	return feed->cb.sec(feed->feed.sec.secbuf, feed->feed.sec.seclen,
			    NULL, 0, &f->filter, &feed->buffer_flags);
}

static int dvb_dmx_swfilter_ip_sectionfilter(struct dvb_demux_feed *feed,
		struct dvb_demux_filter *f)
{
	u8 neq = 0;
	int i;
	u8 index = feed->ip_pid_index;

	for (i = 0; i < DVB_DEMUX_MASK_MAX; i++) {
		u8 xor = f->ip_filter.filter_value[i] ^
			feed->feed.ip_sec.secbuf[index][i];

		if (f->maskandmode[i] & xor)
			return 0;

		neq |= f->maskandnotmode[i] & xor;
	}

	if (f->doneq && !neq)
		return 0;

	return feed->cb.ip_sec(feed->feed.ip_sec.secbuf[index],
			feed->feed.ip_sec.seclen[index],
			NULL, 0, &f->ip_filter, &feed->buffer_flags);
}

static inline int dvb_dmx_swfilter_section_feed(struct dvb_demux_feed *feed)
{
	struct dvb_demux *demux = feed->demux;
	struct dvb_demux_filter *f = feed->filter;
	struct dmx_section_feed *sec = &feed->feed.sec;
	int section_syntax_indicator;

	if (!sec->is_filtering)
		return 0;

	if (!f)
		return 0;

	if (sec->check_crc) {
		section_syntax_indicator = ((sec->secbuf[1] & 0x80) != 0);
		if (section_syntax_indicator &&
		    demux->check_crc32(feed, sec->secbuf, sec->seclen)) {
			set_buf_flags(feed, DMX_BUFFER_FLAG_HAD_CRC32_DISCARD);
			return -1;
		}
	}

	do {
		if (dvb_dmx_swfilter_sectionfilter(feed, f) < 0)
			return -1;
	} while ((f = f->next) && sec->is_filtering);

	sec->seclen = 0;

	return 0;
}

static inline int dvb_dmx_swfilter_ip_section_feed(struct dvb_demux_feed *feed,
		u16 pid)
{
	struct dvb_demux_filter *f = feed->filter;
	struct dmx_ip_section_feed *ip_sec = &feed->feed.ip_sec;
	int section_syntax_indicator;
	u8 index = feed->ip_pid_index;

	if (!ip_sec->is_filtering)
		return 0;

	if (!f)
		return 0;

	if (ip_sec->check_crc) {
		section_syntax_indicator =
			((ip_sec->secbuf[index][1] & 0x80) != 0);
		if (section_syntax_indicator &&
			dvb_dmx_ip_crc32(feed, *(ip_sec->secbuf + index),
				ip_sec->seclen[index], index)){
			return -1;
		}
	}

	while (f && (ip_sec->is_filtering)) {
		if (f->ip_filter.pid == pid) {
			if (dvb_dmx_swfilter_ip_sectionfilter(feed, f) < 0)
					return -1;
			else
				break;
		}
		f = f->next;
	}

	ip_sec->seclen[index] = 0;

	return 0;
}

static void dvb_dmx_swfilter_section_new(struct dvb_demux_feed *feed)
{
	struct dmx_section_feed *sec = &feed->feed.sec;

	if (sec->secbufp < sec->tsfeedp) {
		int n = sec->tsfeedp - sec->secbufp;

		/*
		 * Section padding is done with 0xff bytes entirely.
		 * Due to speed reasons, we won't check all of them
		 * but just first and last.
		 */
		if (sec->secbuf[0] != 0xff || sec->secbuf[n - 1] != 0xff) {
			set_buf_flags(feed,
				      DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED);
			dprintk_sect_loss("section ts padding loss: %d/%d\n",
					  n, sec->tsfeedp);
			dprintk_sect_loss("pad data: %*ph\n", n, sec->secbuf);
		}
	}

	sec->tsfeedp = sec->secbufp = sec->seclen = 0;
	sec->secbuf = sec->secbuf_base;
}

static void dvb_dmx_swfilter_ip_section_new(struct dvb_demux_feed *feed)
{
	struct dmx_ip_section_feed *ip_sec = &feed->feed.ip_sec;
	u8 index = feed->ip_pid_index;

#ifdef DVB_DEMUX_SECTION_LOSS_LOG
	if (ip_sec->secbufp[index] < ip_sec->tsfeedp[index]) {
		int i, n = ip_sec->tsfeedp[index] - ip_sec->secbufp[index];

		/*
		* Section padding is done with 0xff bytes entirely.
		* Due to speed reasons, we won't check all of them
		* but just first and last.
		*/
		if (ip_sec->secbuf[index][0] != 0xff ||
			ip_sec->secbuf[index][n - 1] != 0xff) {
			printk(KERN_INFO "dvb_demux: section ts padding loss: %d/%d\n",
				n, ip_sec->tsfeedp[index]);
			printk(KERN_INFO "dvb_demux: pad data:");
			for (i = 0; i < n; i++)
				printk(KERN_INFO" %02x",
					ip_sec->secbuf[index][i]);
			printk(KERN_INFO"\n");
		}
	}
#endif

	ip_sec->tsfeedp[index] = ip_sec->secbufp[index] =
		ip_sec->seclen[index] = 0;
	ip_sec->secbuf[index] = ip_sec->secbuf_base[index];
}

/*
 * Losless Section Demux 1.4.1 by Emard
 * Valsecchi Patrick:
 *  - middle of section A  (no PUSI)
 *  - end of section A and start of section B
 *    (with PUSI pointing to the start of the second section)
 *
 *  In this case, without feed->pusi_seen you'll receive a garbage section
 *  consisting of the end of section A. Basically because tsfeedp
 *  is incemented and the use=0 condition is not raised
 *  when the second packet arrives.
 *
 * Fix:
 * when demux is started, let feed->pusi_seen = false to
 * prevent initial feeding of garbage from the end of
 * previous section. When you for the first time see PUSI=1
 * then set feed->pusi_seen = true
 */
static int dvb_dmx_swfilter_section_copy_dump(struct dvb_demux_feed *feed,
					      const u8 *buf, u8 len)
{
	struct dvb_demux *demux = feed->demux;
	struct dmx_section_feed *sec = &feed->feed.sec;
	u16 limit, seclen, n;

	if (sec->tsfeedp >= DMX_MAX_SECFEED_SIZE)
		return 0;

	if (sec->tsfeedp + len > DMX_MAX_SECFEED_SIZE) {
		set_buf_flags(feed, DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED);
		dprintk_sect_loss("section buffer full loss: %d/%d\n",
				  sec->tsfeedp + len - DMX_MAX_SECFEED_SIZE,
				  DMX_MAX_SECFEED_SIZE);
		len = DMX_MAX_SECFEED_SIZE - sec->tsfeedp;
	}

	if (len <= 0)
		return 0;

	demux->memcopy(feed, sec->secbuf_base + sec->tsfeedp, buf, len);
	sec->tsfeedp += len;

	/*
	 * Dump all the sections we can find in the data (Emard)
	 */
	limit = sec->tsfeedp;
	if (limit > DMX_MAX_SECFEED_SIZE)
		return -1;	/* internal error should never happen */

	/* to be sure always set secbuf */
	sec->secbuf = sec->secbuf_base + sec->secbufp;

	for (n = 0; sec->secbufp + 2 < limit; n++) {
		seclen = section_length(sec->secbuf);
		if (seclen <= 0 || seclen > DMX_MAX_SECTION_SIZE
		    || seclen + sec->secbufp > limit)
			return 0;
		sec->seclen = seclen;
		sec->crc_val = ~0;
		/* dump [secbuf .. secbuf+seclen) */
		if (feed->pusi_seen[0]) {
			dvb_dmx_swfilter_section_feed(feed);
		} else {
			set_buf_flags(feed,
				      DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED);
			dprintk_sect_loss("pusi not seen, discarding section data\n");
		}
		sec->secbufp += seclen;	/* secbufp and secbuf moving together is */
		sec->secbuf += seclen;	/* redundant but saves pointer arithmetic */
	}

	return 0;
}

static int dvb_dmx_swfilter_ip_section_copy_dump(struct dvb_demux_feed *feed,
		const u8 *buf, u8 len, u16 pid)
{
	struct dvb_demux *demux = feed->demux;
	struct dmx_ip_section_feed *ip_sec = &feed->feed.ip_sec;
	u16 limit, seclen, n;
	u8 index = feed->ip_pid_index;

	if (ip_sec->tsfeedp[index] >= DMX_MAX_SECFEED_SIZE) {
		printk(KERN_ALERT "%s tsfeed greater than max\n", __func__);
		return 0;
	}

	if (ip_sec->tsfeedp[index] + len > DMX_MAX_SECFEED_SIZE) {
#ifdef DVB_DEMUX_SECTION_LOSS_LOG
		printk(KERN_ALERT "dvb_demux: section buffer full loss: %d/%d\n",
			ip_sec->tsfeedp[index] + len - DMX_MAX_SECFEED_SIZE,
			DMX_MAX_SECFEED_SIZE);
#endif
		len = DMX_MAX_SECFEED_SIZE - ip_sec->tsfeedp[index];

	}

	if (len <= 0)
		return 0;

	demux->memcopy(feed, ip_sec->secbuf_base[index] +
			ip_sec->tsfeedp[index],
			buf, len);
	ip_sec->tsfeedp[index] += len;

	/*
	* Dump all the sections we can find in the data (Emard)
	*/
	limit = ip_sec->tsfeedp[index];
	if (limit > DMX_MAX_SECFEED_SIZE) {
		printk("%s limit greater than max sec feed size\n", __func__);
		return -1;	/* internal error should never happen */
	}

	/* to be sure always set secbuf */
	ip_sec->secbuf[index] = ip_sec->secbuf_base[index] +
				ip_sec->secbufp[index];

	for (n = 0; ip_sec->secbufp[index] + 2 < limit; n++) {
		seclen = section_length(ip_sec->secbuf[index]);
		if (seclen <= 16 || seclen > DMX_MAX_SECTION_SIZE
				|| seclen + ip_sec->secbufp[index] > limit) {
			return 0;
		}
		ip_sec->seclen[index] = seclen;
		ip_sec->crc_val[index] = ~0;
		/* dump [secbuf .. secbuf+seclen) */
		if (feed->pusi_seen[index])
			dvb_dmx_swfilter_ip_section_feed(feed, pid);
#ifdef DVB_DEMUX_SECTION_LOSS_LOG
		else
			printk("dvb_demux.c pusi not seen, discarding section data\n");
#endif
		ip_sec->secbufp[index] += seclen;
		/* secbufp and secbuf moving together is */
		ip_sec->secbuf[index] += seclen;
		/* redundant but saves pointer arithmetic */
	}

	return 0;
}

static int dvb_dmx_swfilter_section_packet(struct dvb_demux_feed *feed,
					   const u8 *buf)
{
	u8 p, count;
	int ccok, dc_i = 0;
	u8 cc;

	count = payload(buf);

	if (count == 0)		/* count == 0 if no payload or out of range */
		return -1;

	p = 188 - count;	/* payload start */

	cc = buf[3] & 0x0f;
	ccok = ((feed->cc[0] + 1) & 0x0f) == cc;
	feed->cc[0] = cc;

	if (buf[3] & 0x20) {
		/* adaption field present, check for discontinuity_indicator */
		if ((buf[4] > 0) && (buf[5] & 0x80))
			dc_i = 1;
	}

	if (!ccok || dc_i) {
		if (dc_i) {
			set_buf_flags(feed,
				      DMX_BUFFER_FLAG_DISCONTINUITY_INDICATOR);
			dprintk_sect_loss("%d frame with disconnect indicator\n",
				cc);
		} else {
			set_buf_flags(feed,
				      DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED);
			dprintk_sect_loss("discontinuity: %d instead of %d. %d bytes lost\n",
				cc, (feed->cc[0] + 1) & 0x0f, count + 4);
		}
		/*
		 * those bytes under some circumstances will again be reported
		 * in the following dvb_dmx_swfilter_section_new
		 */

		/*
		 * Discontinuity detected. Reset pusi_seen to
		 * stop feeding of suspicious data until next PUSI=1 arrives
		 *
		 * FIXME: does it make sense if the MPEG-TS is the one
		 *	reporting discontinuity?
		 */

		feed->pusi_seen[0] = false;
		dvb_dmx_swfilter_section_new(feed);
	}

	if (buf[1] & 0x40) {
		/* PUSI=1 (is set), section boundary is here */
		if (count > 1 && buf[p] < count) {
			const u8 *before = &buf[p + 1];
			u8 before_len = buf[p];
			const u8 *after = &before[before_len];
			u8 after_len = count - 1 - before_len;

			dvb_dmx_swfilter_section_copy_dump(feed, before,
							   before_len);
			/* before start of new section, set pusi_seen */
			feed->pusi_seen[0] = true;
			dvb_dmx_swfilter_section_new(feed);
			dvb_dmx_swfilter_section_copy_dump(feed, after,
							   after_len);
		} else if (count > 0) {
			set_buf_flags(feed,
				      DMX_BUFFER_FLAG_DISCONTINUITY_DETECTED);
			dprintk_sect_loss("PUSI=1 but %d bytes lost\n", count);
		}
	} else {
		/* PUSI=0 (is not set), no section boundary */
		dvb_dmx_swfilter_section_copy_dump(feed, &buf[p], count);
	}

	return 0;
}

static int dvb_dmx_swfilter_ip_section_packet(struct dvb_demux_feed *feed,
		const u8 *buf)
{
	u8 p, count;
	int ccok, dc_i = 0;
	u8 cc;
	u16 pid;

	count = payload(buf);

	/* count == 0 if no payload or out of range return -1;*/
	if (count == 0)
		return -1;

	p = 188 - count;	/* payload start */

	cc = buf[3] & 0x0f;
	pid = ts_pid(buf);
	ccok = ((feed->cc[feed->ip_pid_index] + 1) & 0x0f) == cc;
	feed->cc[feed->ip_pid_index] = cc;

	if (buf[3] & 0x20) {
		/* adaption field present, check for discontinuity_indicator */
		if ((buf[4] > 0) && (buf[5] & 0x80))
			dc_i = 1;
	}

	if (!ccok || dc_i) {
#ifdef DVB_DEMUX_SECTION_LOSS_LOG
		printk(KERN_INFO"dvb_demux: discontinuity detected %d bytes lost\n",
				count);
		/*
		* those bytes under sume circumstances will again be reported
		* in the following dvb_dmx_swfilter_section_new
		*/
#endif
		/*
		* Discontinuity detected. Reset pusi_seen = 0 to
		* stop feeding of suspicious data until next PUSI=1 arrives
		*/
		feed->pusi_seen[feed->ip_pid_index] = 0;
		dvb_dmx_swfilter_ip_section_new(feed);
	}

	if (buf[1] & 0x40) {
		/* PUSI=1 (is set), section boundary is here */
		if (count > 1 && buf[p] < count) {
			const u8 *before = &buf[p + 1];
			u8 before_len = buf[p];
			const u8 *after = &before[before_len];
			u8 after_len = count - 1 - before_len;

			dvb_dmx_swfilter_ip_section_copy_dump(feed, before,
					before_len, pid);
			/* before start of new section, set pusi_seen = 1 */
			feed->pusi_seen[feed->ip_pid_index] = 1;
			dvb_dmx_swfilter_ip_section_new(feed);
			dvb_dmx_swfilter_ip_section_copy_dump(feed, after,
					after_len, pid);
		}
#ifdef DVB_DEMUX_SECTION_LOSS_LOG
		else if (count > 0)
			printk(KERN_INFO "dvb_demux: PUSI=1 but %d bytes lost\n", count);
#endif
	} else {
		dvb_dmx_swfilter_ip_section_copy_dump(feed, &buf[p], count,
				pid);
	}

	return 0;
}

static inline void dvb_dmx_swfilter_packet_type(struct dvb_demux_feed *feed,
						const u8 *buf)
{
	switch (feed->type) {
	case DMX_TYPE_TS:
		if (!feed->feed.ts.is_filtering)
			break;
		if (feed->ts_type & TS_PACKET) {
			if (feed->ts_type & TS_PAYLOAD_ONLY)
				dvb_dmx_swfilter_payload(feed, buf);
			else
				feed->cb.ts(buf, 188, NULL, 0, &feed->feed.ts,
					    &feed->buffer_flags);
		}
		/* Used only on full-featured devices */
		if (feed->ts_type & TS_DECODER)
			if (feed->demux->write_to_decoder)
				feed->demux->write_to_decoder(feed, buf, 188);
		break;

	case DMX_TYPE_SEC:
		if (!feed->feed.sec.is_filtering)
			break;
		if (dvb_dmx_swfilter_section_packet(feed, buf) < 0)
			feed->feed.sec.seclen = feed->feed.sec.secbufp = 0;
		break;

	case DMX_TYPE_IP_SEC:
		if (!feed->feed.ip_sec.is_filtering)
			break;
		if (dvb_dmx_swfilter_ip_section_packet(feed, buf) < 0)
			feed->feed.ip_sec.seclen[feed->ip_pid_index] =
			feed->feed.ip_sec.secbufp[feed->ip_pid_index] = 0;
		break;

	default:
		break;
	}
}

#define DVR_FEED(f)							\
	(((f)->type == DMX_TYPE_TS) &&					\
	((f)->feed.ts.is_filtering) &&					\
	(((f)->ts_type & (TS_PACKET | TS_DEMUX)) == TS_PACKET))

static void dvb_dmx_swfilter_packet(struct dvb_demux *demux, const u8 *buf)
{
	struct dvb_demux_feed *feed;
	u16 pid = ts_pid(buf);
	int dvr_done = 0;

	if (dvb_demux_speedcheck) {
		ktime_t cur_time;
		u64 speed_bytes, speed_timedelta;

		demux->speed_pkts_cnt++;

		/* show speed every SPEED_PKTS_INTERVAL packets */
		if (!(demux->speed_pkts_cnt % SPEED_PKTS_INTERVAL)) {
			cur_time = ktime_get();

			if (ktime_to_ns(demux->speed_last_time) != 0) {
				speed_bytes = (u64)demux->speed_pkts_cnt
					* 188 * 8;
				/* convert to 1024 basis */
				speed_bytes = 1000 * div64_u64(speed_bytes,
						1024);
				speed_timedelta = ktime_ms_delta(cur_time,
							demux->speed_last_time);
				if (speed_timedelta)
					dprintk("TS speed %llu Kbits/sec \n",
						div64_u64(speed_bytes,
							  speed_timedelta));
			}

			demux->speed_last_time = cur_time;
			demux->speed_pkts_cnt = 0;
		}
	}

	if (buf[1] & 0x80) {
		list_for_each_entry(feed, &demux->feed_list, list_head) {
			if ((feed->pid != pid) && (feed->pid != 0x2000))
				continue;
			set_buf_flags(feed, DMX_BUFFER_FLAG_TEI);
		}
		dprintk_tscheck("TEI detected. PID=0x%x data1=0x%x\n",
				pid, buf[1]);
		/* data in this packet can't be trusted - drop it unless
		 * module option dvb_demux_feed_err_pkts is set */
		if (!dvb_demux_feed_err_pkts)
			return;
	} else /* if TEI bit is set, pid may be wrong- skip pkt counter */
		if (demux->cnt_storage && dvb_demux_tscheck) {
			/* check pkt counter */
			if (pid < MAX_PID) {
				if (buf[3] & 0x10)
					demux->cnt_storage[pid] =
						(demux->cnt_storage[pid] + 1) & 0xf;

				if ((buf[3] & 0xf) != demux->cnt_storage[pid]) {
					list_for_each_entry(feed, &demux->feed_list, list_head) {
						if ((feed->pid != pid) && (feed->pid != 0x2000))
							continue;
						set_buf_flags(feed,
							      DMX_BUFFER_PKT_COUNTER_MISMATCH);
					}

					dprintk_tscheck("TS packet counter mismatch. PID=0x%x expected 0x%x got 0x%x\n",
							pid, demux->cnt_storage[pid],
							buf[3] & 0xf);
					demux->cnt_storage[pid] = buf[3] & 0xf;
				}
			}
			/* end check */
		}

		list_for_each_entry(feed, &demux->feed_list, list_head) {
		if (feed->type != DMX_TYPE_IP_SEC) {
			if ((feed->pid != pid) && (feed->pid != 0x2000))
				continue;
		}

		/* copy each packet only once to the dvr device, even
		 * if a PID is in multiple filters (e.g. video + PCR) */
		if ((DVR_FEED(feed)) && (dvr_done++))
			continue;

		if (feed->type == DMX_TYPE_IP_SEC) {
			int i = 0;

			while (i < MAX_NUMBER_OF_PID) {
				/* check if received pid is set on the feed */
				if (feed->ip_pid[i] == pid) {
					feed->ip_pid_index = i;
					dvb_dmx_swfilter_packet_type(feed, buf);
					feed->ip_pid_index = 0;
					break;
				} else if (feed->ip_pid[i] == 0x2000)
					feed->cb.ts(buf, 188, NULL, 0,
							&feed->feed.ts, &feed->buffer_flags);
				i++;
			}
		} else {
			feed->ip_pid_index = 0;
			if (feed->pid == pid) {
				if (((feed->pes_type == DMX_PES_PCR0) ||
					(feed->pes_type == DMX_PES_PCR1) ||
					(feed->pes_type == DMX_PES_PCR2) ||
					(feed->pes_type == DMX_PES_PCR3)))
					continue;
				dvb_dmx_swfilter_packet_type(feed, buf);
			} else if (feed->pid == 0x2000)
				feed->cb.ts(buf, 188, NULL, 0, &feed->feed.ts,
						&feed->buffer_flags);
		}
	}
}

void dvb_dmx_swfilter_packets(struct dvb_demux *demux, const u8 *buf,
			      size_t count)
{
	unsigned long flags;

	spin_lock_irqsave(&demux->lock, flags);

	while (count--) {
		if (buf[0] == 0x47)
			dvb_dmx_swfilter_packet(demux, buf);
		buf += 188;
	}

	spin_unlock_irqrestore(&demux->lock, flags);
}

EXPORT_SYMBOL(dvb_dmx_swfilter_packets);

static inline int find_next_packet(const u8 *buf, int pos, size_t count,
				   const int pktsize)
{
	int start = pos, lost;

	while (pos < count) {
		if (buf[pos] == 0x47 ||
		    (pktsize == 204 && buf[pos] == 0xB8))
			break;
		pos++;
	}

	lost = pos - start;
	if (lost) {
		/* This garbage is part of a valid packet? */
		int backtrack = pos - pktsize;
		if (backtrack >= 0 && (buf[backtrack] == 0x47 ||
		    (pktsize == 204 && buf[backtrack] == 0xB8)))
			return backtrack;
	}

	return pos;
}

/* Filter all pktsize= 188 or 204 sized packets and skip garbage. */
static inline void _dvb_dmx_swfilter(struct dvb_demux *demux, const u8 *buf,
		size_t count, const int pktsize)
{
	int p = 0, i, j;
	const u8 *q;
	unsigned long flags;

	spin_lock_irqsave(&demux->lock, flags);

	if (demux->tsbufp) { /* tsbuf[0] is now 0x47. */
		i = demux->tsbufp;
		j = pktsize - i;
		if (count < j) {
			memcpy(&demux->tsbuf[i], buf, count);
			demux->tsbufp += count;
			goto bailout;
		}
		memcpy(&demux->tsbuf[i], buf, j);
		if (demux->tsbuf[0] == 0x47) /* double check */
			dvb_dmx_swfilter_packet(demux, demux->tsbuf);
		demux->tsbufp = 0;
		p += j;
	}

	while (1) {
		p = find_next_packet(buf, p, count, pktsize);
		if (p >= count)
			break;
		if (count - p < pktsize)
			break;

		q = &buf[p];

		if (pktsize == 204 && (*q == 0xB8)) {
			memcpy(demux->tsbuf, q, 188);
			demux->tsbuf[0] = 0x47;
			q = demux->tsbuf;
		}
		dvb_dmx_swfilter_packet(demux, q);
		p += pktsize;
	}

	i = count - p;
	if (i) {
		memcpy(demux->tsbuf, &buf[p], i);
		demux->tsbufp = i;
		if (pktsize == 204 && demux->tsbuf[0] == 0xB8)
			demux->tsbuf[0] = 0x47;
	}

bailout:
	spin_unlock_irqrestore(&demux->lock, flags);
}

void dvb_dmx_swfilter(struct dvb_demux *demux, const u8 *buf, size_t count)
{
	_dvb_dmx_swfilter(demux, buf, count, 188);
}
EXPORT_SYMBOL(dvb_dmx_swfilter);

void dvb_dmx_swfilter_204(struct dvb_demux *demux, const u8 *buf, size_t count)
{
	_dvb_dmx_swfilter(demux, buf, count, 204);
}
EXPORT_SYMBOL(dvb_dmx_swfilter_204);

static inline __u32 iov_crc32( __u32 c, struct kvec *iov, unsigned int cnt )
{
	unsigned int j;
	for (j = 0; j < cnt; j++)
		c = crc32_be( c, iov[j].iov_base, iov[j].iov_len );
	return c;
}

static inline int gse_get_label_length(gse_label_type_t label_type)
{
	switch(label_type)
	{
		/* LT = '00' : 6-Bytes label */
		case GSE_PKT_LABEL_SIX_BYTES :
			return 6;
			break;

		/* LT = '01' : 3-Bytes label */
		case GSE_PKT_LABEL_THREE_BYTES :
			return 3;
			break;

		/* LT = '10' : no label */
		case GSE_PKT_LABEL_NONE :
		/* LT = '11' : label re-use */
		case GSE_PKT_LABEL_REUSE:
			return 0;
			break;

			/* Invalid LT */
		default :
			return -1;
	}
}

/** Prepare for a new  GSE Packet: reset the previous state. */
static inline void reset_gse(struct dvb_demux *demux,u8 frag_id)
{
	struct demux_gse *priv = &demux->gse;
	struct gse_buff *gse_buff_p,*tmp;
	list_for_each_entry_safe(gse_buff_p,tmp,&demux->gse_buff_list,list_head) {
		if(frag_id == gse_buff_p->frag_id)
			list_del(&(gse_buff_p->list_head));
			priv->active_gse_buff_count--;
	}
	kfree(priv->gse_frag_pdu[frag_id]->data);
	priv->gse_frag_pdu[frag_id]->data = NULL;
	priv->gse_frag_pdu[frag_id]->len = 0;
	priv->gse_frag_pdu[frag_id]->tstamp = ktime_set(0,0);
	priv->gse_frag_pdu_count[frag_id] = 0;
	kfree(priv->gse_frag_pdu[frag_id]);
	priv->gse_frag_pdu[frag_id] = NULL;
}

static int dvb_dmx_swfilter_gselabelfilter( const u8 *buf,struct dvb_demux_filter *f,size_t header_len)
{
	u32 header_info = 0;
	u8 gse_label[6];
	int ret = -1;
	int i = 0;
	gse_label_type_t label_type;
	header_info = *buf << 24 | *(buf+1)<<16 | *(buf+2)<<8 | *(buf +3);
	label_type = ((gse_label_type_t)(GSE_LABEL_TYPE(header_info)));
	/* if label filtering is not enabled dump all data */
	if(!f->gselabelfilter.set_label_type)
		return 0;

	if((((f->gselabelfilter.label_type) & GSE_LT_SIX_BYTES) == GSE_LT_SIX_BYTES) && (label_type == GSE_PKT_LABEL_SIX_BYTES)) {
		if(!f->gselabelfilter.mac_count)
			return 0;
		else {
			memcpy(gse_label, buf+header_len, GSE_6_BYTES_LABEL);
			for(i=0;i<f->gselabelfilter.mac_count;i++) {
			if(memcmp(gse_label,f->gselabelfilter.mac_address[i],GSE_6_BYTES_LABEL) == 0)
				return GSE_6_BYTES_LABEL;
			}
			return -1;
		}

	}
	if((((f->gselabelfilter.label_type) & GSE_LT_THREE_BYTES) == GSE_LT_THREE_BYTES)&&(label_type == GSE_PKT_LABEL_THREE_BYTES)) {
		if(!f->gselabelfilter.set_short_mac)
			return 0;
		else {
			memcpy(gse_label,buf+header_len,GSE_3_BYTES_LABEL);
			if(memcmp(gse_label,f->gselabelfilter.short_mac_address,GSE_3_BYTES_LABEL)== 0)
				return GSE_3_BYTES_LABEL;
			else
				ret = -1;
		}
	}
	return ret;
}

static int dvb_dmx_swfilter_gsesectionfilter(struct dvb_demux_feed *feed ,
		const u8 *buf, size_t buf_len,
		struct dvb_demux_filter *f,
		size_t header_len)
{
	u8 neq = 0;
	int i;
	u8 gse_mac[6]= {0};
	u32 header_info = *buf << 24 | *(buf+1)<<16 | *(buf+2)<<8 | *(buf +3);
	gse_label_type_t label_type = ((gse_label_type_t)(GSE_LABEL_TYPE(header_info)));
	u8 label_len = gse_get_label_length(label_type);
	const u8 *ptr = buf + header_len + label_len;

	for (i = 0; i < 18; i++) {
		u8 xor = f->gsefilter.filter_value[i] ^ ptr[i];

		if (f->maskandmode[i] & xor)
			return 0;

		neq |= f->maskandnotmode[i] & xor;
	}

	if (f->doneq && !neq)
		return 0;

	if(memcmp(f->gsefilter.mac_address, gse_mac, 6)) {
		if((label_type == GSE_PKT_LABEL_NONE) ||
			((f->gsefilter.set_short_mac)&&(label_type == GSE_PKT_LABEL_SIX_BYTES)) ||
			((!f->gsefilter.set_short_mac)&&(label_type == GSE_PKT_LABEL_THREE_BYTES)))
			return 0;

		memcpy(gse_mac, buf+header_len, label_len);
		if(memcmp(gse_mac, f->gsefilter.mac_address, label_len)!= 0)
			return 0;
	}
	else if(label_type != GSE_PKT_LABEL_NONE){
			return 0 ;
	}

	if (feed->gse.gse_payload_type & GSE_PAYLOAD_ONLY)
	if (feed->gse.gse_payload_type & GSE_PAYLOAD_ONLY) {
		buf = buf + header_len;
		buf_len-= header_len;
	}

	return feed->cb.gse_sec(buf, buf_len, NULL, 0, &f->gsefilter, &feed->buffer_flags);
}

static inline int  dvb_dmx_swfilter_gsepacket_type(struct dvb_demux_feed *feed,const u8 *buf,size_t buf_len,
					size_t header_len,size_t protocol_type)
{
	struct dmx_gse_feed *gse = &feed->feed.gse;
	struct dvb_demux_filter *f = feed->filter;
	int section_syntax_indicator;
	int len = 0;
	int ret = 0;
	
	switch (feed->gse.type) {
		case DMX_GSE_PDU:
			if (!feed->feed.gse.is_filtering)
				break;
			if(!gse->check_crc) {
				/* Handle protocol filtering */
				if (feed->gse.protocol_type != DMX_NO_PROTOCOL_FILTER)
				{
					if (feed->gse.protocol_type != protocol_type)
						return -1;
				}
				/*handle mac filtering */
				if ((len = dvb_dmx_swfilter_gselabelfilter(buf,f,header_len)) < 0)
					return -1;
				else
					header_len +=len;
			}
			else {
				if((feed->gse.protocol_type == 0x82) || (feed->gse.protocol_type == 0x81))
					return -1;
			}
			feed->cb.gse(buf,buf_len,header_len,&feed->feed.gse,&feed->buffer_flags);
			break;
		case DMX_GSE_NCR:
			if (!feed->feed.gse.is_filtering)
				break;

			feed->cb.gse(buf,buf_len,header_len,&feed->feed.gse,&feed->buffer_flags);
			break;

		case DMX_GSE_SI:
			if ((!feed->feed.gse.is_filtering) || (!f) || (protocol_type != 0x82))
				break;
			gse->crc_val = ~0;
			/* Handle section CRC */
			if (gse->check_crc) {
				section_syntax_indicator = ((buf[header_len + 1] & 0x80) != 0);
				gse->crc_val = crc32_be(gse->crc_val, buf + header_len , buf_len - header_len);
				if (section_syntax_indicator && gse->crc_val)
					return -1;
			}
			do {
				if (dvb_dmx_swfilter_gsesectionfilter(feed,buf,buf_len,f,header_len) < 0)
					return -1;
			} while ((f = f->next) && gse->is_filtering);
			break;

		default:
			break;
	}
	return ret;
}

/**
 * Prepare  GSE full from a GSE Packet
 * Parse GSE packet and allocate buffer for each gse_full packet or for gse_first_fragmeted packet
 * with correct length and copy it into buffer.
 * Assemble fragmented GSE packets varify pdu total length and CRC and handle all error senarios
 * Handling only inoder fragmented packets
 * Handle label reuse senario for full or fragmented GSE packet
 **/
static int _dvb_dmx_swfilter_gse( struct dvb_demux *demux, const u8 *buf, size_t buf_len)
{
	struct demux_gse *priv = &demux->gse;
	struct dvb_demux_feed *feed;
	struct gse_buff *gse_buff_p = NULL;
	enum gse_payload_type payload_type;
	gse_label_type_t label_type;
	u8 header_len = 0;
	u16 gse_sndu_len = 0;
	u16 gse_payload = 0;
	u16 protocol_type = 0;
	u16 to_copy = 0;
	u32 frag_id = FULL_PDU_PACKET_ID;
	u32 gse_pdu_total_len = 0;
	u32 total_len = 0;
	u32 crc_len = 0;
	u32 header_info = 0;
	int ret = 0;
	int label_length =0;
	ktime_t	tstamp = ktime_set(0,0);

	/* Sanity check for arguments */
	if((buf == NULL)||(buf_len == 0)||(buf_len < GSE_MIN_PACKET_LENGTH) ||
			(buf_len > GSE_MAX_PACKET_LENGTH)) {
		dprintk_gsecheck("Invalid GSE packet \n");
		return -EINVAL;
	}

	header_info = *buf << 24 | *(buf+1)<<16 | *(buf+2)<<8 | *(buf +3);
	payload_type = ((enum gse_payload_type)(GSE_PAYLOAD_TYPE(header_info)));
	label_type =  ((gse_label_type_t)(GSE_LABEL_TYPE(header_info)));

	/* Determine the length of the label of the GSE packet */
	label_length = gse_get_label_length(label_type);
	/* Get GSE Packet Length */
	gse_sndu_len = (*buf <<8 | *(buf+1)) & 0x0fff ;

	dprintk_gsecheck("GSE packet length = %lu First 4byte of GSE header = %u\n",
			buf_len,header_info);

	/* finding protocol type,label length and label bits for
	 * 	   full gse packet or 1st frag gse packet */
	if((payload_type == GSE_FULL_PDU) || (payload_type == GSE_FIRST_FRAG_PDU)) {
		header_len = (payload_type == GSE_FULL_PDU) ? GSE_FULL_PDU_HEADER_LENGTH:GSE_FIRST_FRAG_HEADER_LENGTH;
		protocol_type = *(buf + header_len - 2) << 8 | *(buf + header_len - 1);
		/*check for extension header */
		if((protocol_type != 0x82) && (protocol_type != 0x81) && (protocol_type < 0x0600)) {
			dprintk_gsecheck("Unsupported GSE packet \n");
			return -EINVAL;
		}

		if (protocol_type == 0x81)
			gse_sndu_len += 6;

		/* Storing the label and label lenght for label reuse case */
		switch(label_type) {
			case GSE_PKT_LABEL_SIX_BYTES: {
						       priv->gse_label_len = GSE_6_BYTES_LABEL;
						       memcpy(priv->gse_label,buf + header_len,GSE_6_BYTES_LABEL);
					       }
					       break;
			case GSE_PKT_LABEL_THREE_BYTES: {
							 priv->gse_label_len = GSE_3_BYTES_LABEL;
							 memcpy(priv->gse_label,buf + header_len,GSE_3_BYTES_LABEL);
						 }
						 break;

			case GSE_PKT_LABEL_REUSE:
						 gse_sndu_len += priv->gse_label_len;
						 break;

			case GSE_PKT_LABEL_NONE:
						 break;
		}
	}
	else
		header_len = 3;

	/* Handling of DMX_GSE_PDU_CONT dumping the incoming GSE packets as it is
	 * NO Protocol filtering and  mac filtering in this case as protocol type and label comes in first GSE packet In Fragmented case */
	list_for_each_entry(feed, &demux->feed_list, list_head) {
		if ((feed->type == DMX_TYPE_GSE ) && (feed->gse.type == DMX_GSE_PDU_CONT) && (feed->feed.gse.is_filtering)) {
			feed->cb.gse(buf,buf_len,header_len,&feed->feed.gse,&feed->buffer_flags);
		}
	}

	if (payload_type == GSE_FULL_PDU) {
		/* Determine the length of the GSE header */
		header_len = GSE_FULL_PDU_HEADER_LENGTH + label_length;

		dprintk_gsecheck("payload_type = %d label_type = %d header_len = %d\n",
				payload_type, label_type,header_len);

		if((header_len > buf_len)||(gse_sndu_len <= 3) || (gse_sndu_len > GSE_MAX_PACKET_LENGTH-2)) {
			dprintk_gsecheck("buffer len = %lu  is less than header len = %u or invalid gse packet len \n",
					buf_len, header_len);
			return -EINVAL;
		}

		/* Allocate the (decoder target buffer) with the correct size, as follows:
		 * prepare as per label type */
		priv->gse_full_pdu = kzalloc(sizeof(struct gse_buff), GFP_KERNEL);
		if (priv->gse_full_pdu == NULL) {
			dprintk_gsecheck("Memory squeeze, dropping packet.\n");
			return -ENOMEM;
		}
		else {
			priv->gse_full_pdu->data = kzalloc((gse_sndu_len + GSE_MANDATORY_FIELDS_LENGTH),GFP_KERNEL);
			if (priv->gse_full_pdu->data == NULL) {
				kfree(priv->gse_full_pdu);
				priv->gse_full_pdu = NULL;
				dprintk_gsecheck("Memory squeeze, dropping packet.\n");
				return -ENOMEM;
			}
		}
		if(label_type != GSE_PKT_LABEL_REUSE) {
			/* copy the full GSE packet into buffer gse packet lenght + 2:GSE_MANDATORY_FIELDS_LENGTH */
			memcpy(priv->gse_full_pdu->data,buf,(gse_sndu_len + GSE_MANDATORY_FIELDS_LENGTH));
			priv->gse_full_pdu->len = gse_sndu_len + GSE_MANDATORY_FIELDS_LENGTH;
		}
		else {
			/* In this case first copy header Information that is 4 bytes:GSE_FULL_PDU_HEADER_LENGTH  */
			memcpy(priv->gse_full_pdu->data,buf,GSE_FULL_PDU_HEADER_LENGTH);
			priv->gse_full_pdu->len = GSE_FULL_PDU_HEADER_LENGTH;
			/* Insert the previous saved label after protocol type field */
			memcpy(priv->gse_full_pdu->data + priv->gse_full_pdu->len,priv->gse_label,priv->gse_label_len);
			priv->gse_full_pdu->len += priv->gse_label_len;
			to_copy = (gse_sndu_len - (GSE_PROTOCOL_TYPE_LENGTH + priv->gse_label_len));
			/* Copy the Payload after label field */
			memcpy(priv->gse_full_pdu->data + priv->gse_full_pdu->len,(buf+ GSE_FULL_PDU_HEADER_LENGTH),to_copy);
			priv->gse_full_pdu->len += to_copy;
		}

		list_for_each_entry(feed, &demux->feed_list, list_head) {
			if ((feed->type == DMX_TYPE_GSE ) && (feed->gse.type != DMX_GSE_PDU_CONT)
					&& (feed->feed.gse.is_filtering)) {
				dvb_dmx_swfilter_gsepacket_type(feed,priv->gse_full_pdu->data,priv->gse_full_pdu->len,
						GSE_FULL_PDU_HEADER_LENGTH,protocol_type);
			}
		}
		/* Free and reset buffer structure  after processing packet for all filters opened on GSE feed */
		kfree(priv->gse_full_pdu->data);
		priv->gse_full_pdu->data = NULL;
		priv->gse_full_pdu->len = 0;
		kfree(priv->gse_full_pdu);
		priv->gse_full_pdu = NULL;
	}
	else {
		frag_id = *(buf + GSE_MANDATORY_FIELDS_LENGTH);
		if(payload_type == GSE_FIRST_FRAG_PDU) {

			/*calculate by sum of mandatory header field in case of first fragment and label lenght */
			header_len = GSE_FIRST_FRAG_HEADER_LENGTH + label_length;

			dprintk_gsecheck("payload_type = %d label_type = %d header_len = %d\n",
					payload_type, label_type,header_len);

			/* PDU total length  3rd and 4th byte of Gse packet */
			gse_pdu_total_len =  *(buf + 3) << 8 | *(buf + 4);

			if((gse_pdu_total_len > GSE_MAX_PDU_LENGTH ) || (header_len > buf_len)) {
				dprintk_gsecheck("Invalid GSE packet len or invalid total length \n");
				return -EINVAL;
			}

			/* Handling Restart case : when start of pdu is coming again for the same Frag id
			 * In this case we must discard already assembled pdu and reset the structures
			 * and start fresh assembling of pdu.
			 */
			if(priv->gse_frag_pdu[frag_id] != NULL)
				reset_gse(demux,frag_id);

			/* prepare buffer as per label type */
			header_len += (label_type == GSE_PKT_LABEL_REUSE) ? priv->gse_label_len:0;

			/* Allocate the buffer (decoder target buffer) with the correct size, as follows:*/
			priv->gse_frag_pdu[frag_id] = kzalloc(sizeof(struct gse_buff), GFP_KERNEL);
			if (priv->gse_frag_pdu[frag_id] == NULL) {
				dprintk_gsecheck("Memory squeeze, dropping packet.\n");
				return -ENOMEM;
			}
			else {
				priv->gse_frag_pdu[frag_id]->data = kzalloc((gse_pdu_total_len + header_len + GSE_MAX_TRAILER_LENGTH),
									GFP_KERNEL);
				if (priv->gse_frag_pdu[frag_id]->data == NULL) {
					kfree(priv->gse_frag_pdu[frag_id]);
					dprintk_gsecheck("Memory squeeze, dropping packet.\n");
					return -ENOMEM;
				}
			}
			priv->gse_frag_pdu[frag_id]->frag_id = frag_id;
			list_add(&(priv->gse_frag_pdu[frag_id]->list_head),&demux->gse_buff_list);
			priv->active_gse_buff_count++;
			if(label_type != GSE_PKT_LABEL_REUSE) {
				/* copy the first full GSE packet into buffer */
				memcpy(priv->gse_frag_pdu[frag_id]->data,
						buf,(gse_sndu_len + GSE_MANDATORY_FIELDS_LENGTH));
				priv->gse_frag_pdu[frag_id]->len = gse_sndu_len + GSE_MANDATORY_FIELDS_LENGTH;
			}
			else {
				gse_sndu_len -=  priv->gse_label_len;
				/* In this case first copy header Information that is 7 bytes:GSE_FIRST_FRAG_HEADER_LENGTH  */
				memcpy(priv->gse_frag_pdu[frag_id]->data,
						buf,GSE_FIRST_FRAG_HEADER_LENGTH);
				priv->gse_frag_pdu[frag_id]->len = GSE_FIRST_FRAG_HEADER_LENGTH;
				/* Insert the previous saved label after protocol type field */
				memcpy(priv->gse_frag_pdu[frag_id]->data + priv->gse_frag_pdu[frag_id]->len,
						priv->gse_label,priv->gse_label_len);
				priv->gse_frag_pdu[frag_id]->len += priv->gse_label_len;
				/*No label lenth in this packet so pdu length =  gse packet_len - these header fields */
				to_copy = (gse_sndu_len - ( GSE_FRAG_ID_LENGTH + GSE_TOTAL_LENGTH_LENGTH + GSE_PROTOCOL_TYPE_LENGTH));
				/* Insert the payload after label filed 7:GSE_FIRST_FRAG_HEADER_LENGTH*/
				memcpy(priv->gse_frag_pdu[frag_id]->data + priv->gse_frag_pdu[frag_id]->len,(buf+GSE_FIRST_FRAG_HEADER_LENGTH),to_copy);
				priv->gse_frag_pdu[frag_id]->len += to_copy;
				/* Set the label field accordingly this will help us calculating total pdu lenght */
				priv->gse_frag_pdu[frag_id]->data[0] &= (priv->gse_label_len == GSE_6_BYTES_LABEL) ? 0xcf:0xdf;
				/*Set the end bit to indicate that label field is added by dvb_net and not part of orignal gse packet
				 * 				  This will help us during CRC calculation*/
				priv->gse_frag_pdu[frag_id]->data[0] |= GSE_END_BIT_MANUALY_SET;
			}
			priv->gse_frag_pdu_count[frag_id]++;
			/* Store the time stamp */
			priv->gse_frag_pdu[frag_id]->tstamp = ktime_get_real();
		}
		else {
			/* Packet coming before 1st Fragment or coming after drop of partial packet */
			/*Handle Padding Case when S,B and label type are all 0.*/
			if((priv->gse_frag_pdu[frag_id] == NULL) || (label_type !=  GSE_PKT_LABEL_REUSE)) {
				dprintk_gsecheck("Invalid case \n");
				return -EINVAL;
			}
			/*Handling of Case GSE packet coming after  more then 64 baseband frames from the start of first fragment */
			tstamp = ktime_get_real();
			/* For fragmented packet payload will be always GSE Packet length - 1byte fragment ID*/
			gse_payload =  gse_sndu_len - GSE_FRAG_ID_LENGTH;
			label_length = gse_get_label_length((priv->gse_frag_pdu[frag_id]->data[0] & GSE_LABEL_BITS)>>4);

			crc_len = (payload_type == GSE_LAST_FRAG_PDU ) ? GSE_MAX_TRAILER_LENGTH:0;

			if(priv->gse_frag_pdu[frag_id]->data[0] & GSE_END_BIT_MANUALY_SET)
				total_len = (priv->gse_frag_pdu[frag_id]->len + gse_payload) - crc_len - label_length -5;
			else
				total_len = (priv->gse_frag_pdu[frag_id]->len + gse_payload) - crc_len - 5;

			/* Check for payload lenght is not exceding the max limit or not exceding the max time */
			if((total_len > GSE_MAX_PDU_LENGTH) || (ktime_to_ms(ktime_sub(tstamp,priv->gse_frag_pdu[frag_id]->tstamp)) > GSE_PACKET_MAX_TIMEOUT))
			{
				dprintk_gsecheck("pdu overflow or max time out reached \n");
				reset_gse(demux,frag_id);
				return -EINVAL;
			}
			if (payload_type == GSE_NEXT_FRAG_PDU) {
				priv->gse_frag_pdu_count[frag_id]++;
				/* Check count is not exceding 6:GSE_MAX_FRAGMENT_COUNT */
				if(priv->gse_frag_pdu_count[frag_id] >= GSE_MAX_FRAGMENT_COUNT) {
					dprintk_gsecheck("pdu max fragmentation count reached \n");
					reset_gse(demux,frag_id);
					return -EINVAL;
				}
				/* Every thing ok now copy the pdu into buffer */
				memcpy(priv->gse_frag_pdu[frag_id]->data + priv->gse_frag_pdu[frag_id]->len,
						(buf + GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH),gse_payload);
				priv->gse_frag_pdu[frag_id]->len += gse_payload;
			}
			else {
				/* Handling  GSE Profile
				 * http://www.etsi.org/deliver/etsi_ts/102600_102699/10260601/01.02.01_60/ts_10260601v010201p.pdf
				 * The maximum number of concurrent Fragmentation Identifiers (Frag ID) shall be 256
				 * The maximum number of PDU fragments with the same Frag ID can be unlimited but restricted to
				 * 0xFFFF and Max. Delay for final frag transmission is equivalent to 256 baseband frames
				 */
				priv->gse_frag_pdu_count[frag_id] ++;
				/* PDU total length  3rd and 4th byte of Gse packet */
				gse_pdu_total_len =  *(priv->gse_frag_pdu[frag_id]->data + 3) << 8 | *(priv->gse_frag_pdu[frag_id]->data + 4);

				if((gse_pdu_total_len == total_len)
						&& (priv->gse_frag_pdu_count[frag_id] <= GSE_MAX_FRAGMENT_COUNT)) {

					/* Check CRC32,with the CRC value of GSE packet received in last four bytes */
					const u8 *tail;
					struct kvec iov_label_reuse[2] = {
						/*CRC is to be computed over these field
						 * GSE_TOTAL_LENGTH GSE_PROTOCOL_TYPE PDU
						 * Label field will not be part of CRC in this case as it was
						 * Manualy inserted based on label reuse */
						{priv->gse_frag_pdu[frag_id]->data + GSE_TOTAL_LENGTH_OFFSET,
							(GSE_TOTAL_LENGTH_LENGTH + GSE_PROTOCOL_TYPE_LENGTH)},

						{priv->gse_frag_pdu[frag_id]->data + (GSE_FIRST_FRAG_HEADER_LENGTH + label_length),
							(priv->gse_frag_pdu[frag_id]->len + gse_payload) -
								(label_length + GSE_FIRST_FRAG_HEADER_LENGTH + GSE_MAX_TRAILER_LENGTH)}
					};

					struct kvec iov[1] = {
						/*CRC is to be computed over these field
						 *GSE_TOTAL_LENGTH GSE_PROTOCOL_TYPE Label Field PDU */
						{ priv->gse_frag_pdu[frag_id]->data + GSE_TOTAL_LENGTH_OFFSET,
							(priv->gse_frag_pdu[frag_id]->len + gse_payload) -
								(GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH + GSE_MAX_TRAILER_LENGTH)}
					};
					u32 gse_crc = ~0L, expected_crc;
					/* copy the last fragment into buffer and compute CRC over it */
					memcpy(priv->gse_frag_pdu[frag_id]->data +  priv->gse_frag_pdu[frag_id]->len,
							(buf + (GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH)),gse_payload);
					priv->gse_frag_pdu[frag_id]->len += gse_payload;

					/* Get the last 4 bytes of buffer to get CRC from Gse Packet */
					tail = priv->gse_frag_pdu[frag_id]->data + priv->gse_frag_pdu[frag_id]->len;
					expected_crc = *(tail - 4) << 24 |
						*(tail - 3) << 16 |
						*(tail - 2) << 8 |
						*(tail - 1);
					/* Drop the last 4 bytes of buffer as it will not be pushed to network stack and not part of GSE-SI
					 * and will not be part of CRC computation */
					priv->gse_frag_pdu[frag_id]->len  -= GSE_MAX_TRAILER_LENGTH;
					/* Prepare for crc validation dependng upon label reuse */
					if(priv->gse_frag_pdu[frag_id]->data[0] & GSE_END_BIT_MANUALY_SET)
						gse_crc = iov_crc32(gse_crc, iov_label_reuse, 2);
					else
						gse_crc = iov_crc32(gse_crc, iov, 1);
					if(gse_crc != expected_crc) {
						dprintk_gsecheck("CRC32 check FAILED: %08x / %08x, SNDU len %d \n",
								gse_crc, expected_crc, priv->gse_frag_pdu[frag_id]->len);
						reset_gse(demux,frag_id);
						return  -EINVAL;
					}
					else {
						protocol_type = priv->gse_frag_pdu[frag_id]->data[5] << 8 |  priv->gse_frag_pdu[frag_id]->data[6];
						list_for_each_entry(feed, &demux->feed_list, list_head) {
							if ((feed->type == DMX_TYPE_GSE ) && ((feed->gse.type == DMX_GSE_SI) || (feed->gse.type == DMX_GSE_PDU))
									&& (feed->feed.gse.is_filtering)) {
								dvb_dmx_swfilter_gsepacket_type(feed,priv->gse_frag_pdu[frag_id]->data,
										priv->gse_frag_pdu[frag_id]->len,
										GSE_FIRST_FRAG_HEADER_LENGTH,protocol_type);
							}
						}
						/* Free and reset buffer structure  after processing packet for all filters opened on GSE feed */
						reset_gse(demux,frag_id);
					}

				}
				else {
					dprintk_gsecheck("Invalid pdu assembely\n");
					reset_gse(demux,frag_id);
					return -EINVAL;
				}
			}
		}
		/*  Handling of case Gse packet stop coming for some frag-ids
		 *  For this mantaine list of all frag ids
		 *  Add frag id at time of first fragment handling
		 *  remove frag id at time of submitting it to network
		 *  and Scan all fragids here that are not submitted to network stack
		 *  and compare the timestamp remove those fragid and  buffers which exceeds timeout */
		if(priv->active_gse_buff_count) {
			tstamp = ktime_get_real();
			list_for_each_entry(gse_buff_p,&demux->gse_buff_list,list_head) {
				if (ktime_to_ms(ktime_sub(tstamp,gse_buff_p->tstamp)) > GSE_PACKET_MAX_TIMEOUT) {
					list_del(&gse_buff_p->list_head);
					kfree(priv->gse_frag_pdu[gse_buff_p->frag_id]->data);
					priv->gse_frag_pdu[gse_buff_p->frag_id]->data = NULL;
					priv->gse_frag_pdu[gse_buff_p->frag_id]->len = 0;
					priv->gse_frag_pdu[gse_buff_p->frag_id]->tstamp = ktime_set(0,0);
					priv->gse_frag_pdu_count[gse_buff_p->frag_id] = 0;
					kfree(priv->gse_frag_pdu[gse_buff_p->frag_id]);
					priv->gse_frag_pdu[gse_buff_p->frag_id] = NULL;
				}
			}
		}
	}
	return ret;
}

void dvb_dmx_swfilter_gse(struct dvb_demux *demux, const u8 *buf, size_t len)
{
	struct dvb_demux_feed *feed;
	int gse_feed_set = 0;
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&demux->lock, flags);

	list_for_each_entry(feed, &demux->feed_list, list_head) {
		if (feed->type != DMX_TYPE_GSE )
			continue;
		else
		{	gse_feed_set = 1;
			break;
		}
	}

	if(gse_feed_set)
	{
		dprintk_gsecheck("GSE packet len %d\n", len);
		ret = _dvb_dmx_swfilter_gse(demux, buf, len);
	}

	spin_unlock_irqrestore(&demux->lock, flags);
}
EXPORT_SYMBOL(dvb_dmx_swfilter_gse);

void dvb_dmx_swfilter_raw(struct dvb_demux *demux, const u8 *buf, size_t count)
{
	unsigned long flags;

	spin_lock_irqsave(&demux->lock, flags);

	demux->feed->cb.ts(buf, count, NULL, 0, &demux->feed->feed.ts,
			   &demux->feed->buffer_flags);

	spin_unlock_irqrestore(&demux->lock, flags);
}
EXPORT_SYMBOL(dvb_dmx_swfilter_raw);

static struct dvb_demux_filter *dvb_dmx_filter_alloc(struct dvb_demux *demux)
{
	int i;

	for (i = 0; i < demux->filternum; i++)
		if (demux->filter[i].state == DMX_STATE_FREE)
			break;

	if (i == demux->filternum)
		return NULL;

	demux->filter[i].state = DMX_STATE_ALLOCATED;

	return &demux->filter[i];
}

static struct dvb_demux_feed *dvb_dmx_feed_alloc(struct dvb_demux *demux)
{
	int i;

	for (i = 0; i < demux->feednum; i++)
		if (demux->feed[i].state == DMX_STATE_FREE)
			break;

	if (i == demux->feednum)
		return NULL;

	demux->feed[i].state = DMX_STATE_ALLOCATED;

	return &demux->feed[i];
}

static int dvb_demux_feed_find(struct dvb_demux_feed *feed)
{
	struct dvb_demux_feed *entry;

	list_for_each_entry(entry, &feed->demux->feed_list, list_head)
		if (entry == feed)
			return 1;

	return 0;
}

static void dvb_demux_feed_add(struct dvb_demux_feed *feed)
{
	spin_lock_irq(&feed->demux->lock);
	if (dvb_demux_feed_find(feed)) {
		pr_err("%s: feed already in list (type=%x state=%x pid=%x)\n",
		       __func__, feed->type, feed->state, feed->pid);
		goto out;
	}

	list_add(&feed->list_head, &feed->demux->feed_list);
out:
	spin_unlock_irq(&feed->demux->lock);
}

static void dvb_demux_feed_del(struct dvb_demux_feed *feed)
{
	spin_lock_irq(&feed->demux->lock);
	if (!(dvb_demux_feed_find(feed))) {
		pr_err("%s: feed not in list (type=%x state=%x pid=%x)\n",
		       __func__, feed->type, feed->state, feed->pid);
		goto out;
	}

	list_del(&feed->list_head);
out:
	spin_unlock_irq(&feed->demux->lock);
}

static int dmx_ts_feed_set(struct dmx_ts_feed *ts_feed, u16 pid, int ts_type,
			   enum dmx_ts_pes pes_type, ktime_t timeout)
{
	struct dvb_demux_feed *feed = (struct dvb_demux_feed *)ts_feed;
	struct dvb_demux *demux = feed->demux;

	if (pid > DMX_MAX_PID)
		return -EINVAL;

	if (mutex_lock_interruptible(&demux->mutex))
		return -ERESTARTSYS;

	if (ts_type & TS_DECODER) {
		if (pes_type >= DMX_PES_OTHER) {
			mutex_unlock(&demux->mutex);
			return -EINVAL;
		}

		if (demux->pesfilter[pes_type] &&
		    demux->pesfilter[pes_type] != feed) {
			mutex_unlock(&demux->mutex);
			return -EINVAL;
		}

		demux->pesfilter[pes_type] = feed;
		demux->pids[pes_type] = pid;
	}

	dvb_demux_feed_add(feed);

	feed->pid = pid;
	feed->timeout = timeout;
	feed->ts_type = ts_type;
	feed->pes_type = pes_type;

	feed->state = DMX_STATE_READY;
	mutex_unlock(&demux->mutex);

	return 0;
}

static int dmx_ts_feed_start_filtering(struct dmx_ts_feed *ts_feed)
{
	struct dvb_demux_feed *feed = (struct dvb_demux_feed *)ts_feed;
	struct dvb_demux *demux = feed->demux;
	int ret;

	if (mutex_lock_interruptible(&demux->mutex))
		return -ERESTARTSYS;

	if (feed->state != DMX_STATE_READY || feed->type != DMX_TYPE_TS) {
		mutex_unlock(&demux->mutex);
		return -EINVAL;
	}

	if (!demux->start_feed) {
		mutex_unlock(&demux->mutex);
		return -ENODEV;
	}

	if ((ret = demux->start_feed(feed)) < 0) {
		mutex_unlock(&demux->mutex);
		return ret;
	}

	spin_lock_irq(&demux->lock);
	ts_feed->is_filtering = 1;
	feed->state = DMX_STATE_GO;
	spin_unlock_irq(&demux->lock);
	mutex_unlock(&demux->mutex);

	return 0;
}

static int dmx_ts_feed_stop_filtering(struct dmx_ts_feed *ts_feed)
{
	struct dvb_demux_feed *feed = (struct dvb_demux_feed *)ts_feed;
	struct dvb_demux *demux = feed->demux;
	int ret;

	mutex_lock(&demux->mutex);

	if (feed->state < DMX_STATE_GO) {
		mutex_unlock(&demux->mutex);
		return -EINVAL;
	}

	if (!demux->stop_feed) {
		mutex_unlock(&demux->mutex);
		return -ENODEV;
	}

	ret = demux->stop_feed(feed);

	spin_lock_irq(&demux->lock);
	ts_feed->is_filtering = 0;
	feed->state = DMX_STATE_ALLOCATED;
	spin_unlock_irq(&demux->lock);
	mutex_unlock(&demux->mutex);

	return ret;
}

static int dvbdmx_allocate_ts_feed(struct dmx_demux *dmx,
				   struct dmx_ts_feed **ts_feed,
				   dmx_ts_cb callback)
{
	struct dvb_demux *demux = (struct dvb_demux *)dmx;
	struct dvb_demux_feed *feed;

	if (mutex_lock_interruptible(&demux->mutex))
		return -ERESTARTSYS;

	if (!(feed = dvb_dmx_feed_alloc(demux))) {
		mutex_unlock(&demux->mutex);
		return -EBUSY;
	}

	feed->type = DMX_TYPE_TS;
	feed->cb.ts = callback;
	feed->demux = demux;
	feed->pid = 0xffff;
	feed->peslen = 0xfffa;
	feed->buffer_flags = 0;

	(*ts_feed) = &feed->feed.ts;
	(*ts_feed)->parent = dmx;
	(*ts_feed)->priv = NULL;
	(*ts_feed)->is_filtering = 0;
	(*ts_feed)->start_filtering = dmx_ts_feed_start_filtering;
	(*ts_feed)->stop_filtering = dmx_ts_feed_stop_filtering;
	(*ts_feed)->set = dmx_ts_feed_set;

	if (!(feed->filter = dvb_dmx_filter_alloc(demux))) {
		feed->state = DMX_STATE_FREE;
		mutex_unlock(&demux->mutex);
		return -EBUSY;
	}

	feed->filter->type = DMX_TYPE_TS;
	feed->filter->feed = feed;
	feed->filter->state = DMX_STATE_READY;

	mutex_unlock(&demux->mutex);

	return 0;
}

static int dvbdmx_release_ts_feed(struct dmx_demux *dmx,
				  struct dmx_ts_feed *ts_feed)
{
	struct dvb_demux *demux = (struct dvb_demux *)dmx;
	struct dvb_demux_feed *feed = (struct dvb_demux_feed *)ts_feed;

	mutex_lock(&demux->mutex);

	if (feed->state == DMX_STATE_FREE) {
		mutex_unlock(&demux->mutex);
		return -EINVAL;
	}

	feed->state = DMX_STATE_FREE;
	feed->filter->state = DMX_STATE_FREE;

	dvb_demux_feed_del(feed);

	feed->pid = 0xffff;

	if (feed->ts_type & TS_DECODER && feed->pes_type < DMX_PES_OTHER)
		demux->pesfilter[feed->pes_type] = NULL;

	mutex_unlock(&demux->mutex);
	return 0;
}

/******************************************************************************
 * dmx_section_feed API calls
 ******************************************************************************/

static int dmx_section_feed_allocate_filter(struct dmx_section_feed *feed,
					    struct dmx_section_filter **filter)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdemux = dvbdmxfeed->demux;
	struct dvb_demux_filter *dvbdmxfilter;

	if (mutex_lock_interruptible(&dvbdemux->mutex))
		return -ERESTARTSYS;

	dvbdmxfilter = dvb_dmx_filter_alloc(dvbdemux);
	if (!dvbdmxfilter) {
		mutex_unlock(&dvbdemux->mutex);
		return -EBUSY;
	}

	spin_lock_irq(&dvbdemux->lock);
	*filter = &dvbdmxfilter->filter;
	(*filter)->parent = feed;
	(*filter)->priv = NULL;
	dvbdmxfilter->feed = dvbdmxfeed;
	dvbdmxfilter->type = DMX_TYPE_SEC;
	dvbdmxfilter->state = DMX_STATE_READY;
	dvbdmxfilter->next = dvbdmxfeed->filter;
	dvbdmxfeed->filter = dvbdmxfilter;
	spin_unlock_irq(&dvbdemux->lock);

	mutex_unlock(&dvbdemux->mutex);
	return 0;
}

static int dmx_ip_section_feed_allocate_filter(struct dmx_ip_section_feed *feed,
		struct dmx_ip_section_filter **filter)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdemux = dvbdmxfeed->demux;
	struct dvb_demux_filter *dvbdmxfilter;

	if (mutex_lock_interruptible(&dvbdemux->mutex))
		return -ERESTARTSYS;

	dvbdmxfilter = dvb_dmx_filter_alloc(dvbdemux);
	if (!dvbdmxfilter) {
		mutex_unlock(&dvbdemux->mutex);
		return -EBUSY;
	}

	spin_lock_irq(&dvbdemux->lock);
	*filter = &dvbdmxfilter->ip_filter;
	(*filter)->parent = feed;
	(*filter)->priv = NULL;
	dvbdmxfilter->feed = dvbdmxfeed;
	dvbdmxfilter->type = DMX_TYPE_IP_SEC;
	dvbdmxfilter->state = DMX_STATE_READY;
	dvbdmxfilter->next = dvbdmxfeed->filter;
	dvbdmxfeed->filter = dvbdmxfilter;
	spin_unlock_irq(&dvbdemux->lock);

	mutex_unlock(&dvbdemux->mutex);
	return 0;
}
static int dmx_gse_feed_allocate_secfilter(struct dmx_gse_feed *feed,
					    struct dmx_gsesection_filter **filter)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdemux = dvbdmxfeed->demux;
	struct dvb_demux_filter *dvbdmxfilter;

	if (mutex_lock_interruptible(&dvbdemux->mutex))
		return -ERESTARTSYS;

	dvbdmxfilter = dvb_dmx_filter_alloc(dvbdemux);
	if (!dvbdmxfilter) {
		mutex_unlock(&dvbdemux->mutex);
		return -EBUSY;
	}

	spin_lock_irq(&dvbdemux->lock);
	*filter = &dvbdmxfilter->gsefilter;
	(*filter)->parent = feed;
	(*filter)->priv = NULL;
	dvbdmxfilter->feed = dvbdmxfeed;
	dvbdmxfilter->type = DMX_TYPE_GSE;
	dvbdmxfilter->state = DMX_STATE_READY;
	dvbdmxfilter->next = dvbdmxfeed->filter;
	dvbdmxfeed->filter = dvbdmxfilter;
	spin_unlock_irq(&dvbdemux->lock);

	mutex_unlock(&dvbdemux->mutex);
	return 0;
}

static int dmx_gse_feed_allocate_labelfilter(struct dmx_gse_feed *feed,
					    struct dmx_gselabel_filter **filter)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdemux = dvbdmxfeed->demux;
	struct dvb_demux_filter *dvbdmxfilter;

	if (mutex_lock_interruptible(&dvbdemux->mutex))
		return -ERESTARTSYS;

	dvbdmxfilter = dvb_dmx_filter_alloc(dvbdemux);
	if (!dvbdmxfilter) {
		mutex_unlock(&dvbdemux->mutex);
		return -EBUSY;
	}

	spin_lock_irq(&dvbdemux->lock);
	*filter = &dvbdmxfilter->gselabelfilter;
	(*filter)->parent = feed;
	(*filter)->priv = NULL;
	dvbdmxfilter->feed = dvbdmxfeed;
	dvbdmxfilter->type = DMX_TYPE_GSE;
	dvbdmxfilter->state = DMX_STATE_READY;
	dvbdmxfilter->next = dvbdmxfeed->filter;
	dvbdmxfeed->filter = dvbdmxfilter;
	spin_unlock_irq(&dvbdemux->lock);

	mutex_unlock(&dvbdemux->mutex);
	return 0;
}

static int dmx_section_feed_set(struct dmx_section_feed *feed,
				u16 pid, int check_crc)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;

	if (pid > 0x1fff)
		return -EINVAL;

	if (mutex_lock_interruptible(&dvbdmx->mutex))
		return -ERESTARTSYS;

	dvb_demux_feed_add(dvbdmxfeed);

	dvbdmxfeed->pid = pid;
	dvbdmxfeed->feed.sec.check_crc = check_crc;

	dvbdmxfeed->state = DMX_STATE_READY;
	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dmx_ip_section_feed_set(struct dmx_ip_section_feed *feed,
				u16 *pid, u8 no_of_pid, int check_crc)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	int i = 0;
	u16 *temp = pid;

	if (no_of_pid > MAX_NUMBER_OF_PID) {
		printk(KERN_ALERT"Max number of IP pid exceeds\n");
		return -EINVAL;
	}
	for (i = 0; i < no_of_pid; i++) {
		if (*temp > 0x1fff)
			return -EINVAL;
		temp++;
	}

	if (mutex_lock_interruptible(&dvbdmx->mutex))
		return -ERESTARTSYS;

	dvb_demux_feed_add(dvbdmxfeed);

	memset(&dvbdmxfeed->ip_new_pid[0],
			0xffff, sizeof(u16) * MAX_NUMBER_OF_PID);
	for (i = 0; i < no_of_pid; i++) {
		dvbdmxfeed->ip_new_pid[i] = *pid;
		pid++;
	}	
	if (!dvbdmxfeed->feed.ip_sec.runtime_pid_change)
		memcpy(&dvbdmxfeed->ip_pid[0],
			&dvbdmxfeed->ip_new_pid[0],
				sizeof(u16) *MAX_NUMBER_OF_PID);
	dvbdmxfeed->feed.ip_sec.check_crc = check_crc;

	dvbdmxfeed->state = DMX_STATE_READY;
	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static void prepare_secfilters(struct dvb_demux_feed *dvbdmxfeed)
{
	int i;
	struct dvb_demux_filter *f;
	struct dmx_section_filter *sf;
	u8 mask, mode, doneq;

	if (!(f = dvbdmxfeed->filter))
		return;
	do {
		sf = &f->filter;
		doneq = false;
		for (i = 0; i < DVB_DEMUX_MASK_MAX; i++) {
			mode = sf->filter_mode[i];
			mask = sf->filter_mask[i];
			f->maskandmode[i] = mask & mode;
			doneq |= f->maskandnotmode[i] = mask & ~mode;
		}
		f->doneq = doneq ? true : false;
	} while ((f = f->next));
}

static void prepare_ip_secfilters(struct dvb_demux_feed *dvbdmxfeed)
{
	int i;
	struct dvb_demux_filter *f;
	struct dmx_ip_section_filter *sf;
	u8 mask, mode, doneq;

	f = dvbdmxfeed->filter;
	if (!f)
		return;
	do {
		sf = &f->ip_filter;
		doneq = 0;
		for (i = 0; i < DVB_DEMUX_MASK_MAX; i++) {
			mode = sf->filter_mode[i];
			mask = sf->filter_mask[i];
			f->maskandmode[i] = mask & mode;
			doneq |= f->maskandnotmode[i] = mask & ~mode;
		}
		f->doneq = doneq ? 1 : 0;
	} while ((f = f->next));
}

static void prepare_gsesecfilters(struct dvb_demux_feed *dvbdmxfeed)
{
        int i;
        struct dvb_demux_filter *f;
        struct dmx_gsesection_filter *sf;
        u8 mask, mode, doneq;

        if (!(f = dvbdmxfeed->filter))
                return;
        do {
                sf = &f->gsefilter;
                doneq = 0;
                for (i = 0; i < DVB_DEMUX_MASK_MAX; i++) {
                        mode = sf->filter_mode[i];
                        mask = sf->filter_mask[i];
                        f->maskandmode[i] = mask & mode;
                        doneq |= f->maskandnotmode[i] = mask & ~mode;
                }
                f->doneq = doneq ? 1 : 0;
        } while ((f = f->next));
}

static int dmx_section_feed_start_filtering(struct dmx_section_feed *feed)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	int ret;

	if (mutex_lock_interruptible(&dvbdmx->mutex))
		return -ERESTARTSYS;

	if (feed->is_filtering) {
		mutex_unlock(&dvbdmx->mutex);
		return -EBUSY;
	}

	if (!dvbdmxfeed->filter) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}

	dvbdmxfeed->feed.sec.tsfeedp = 0;
	dvbdmxfeed->feed.sec.secbuf = dvbdmxfeed->feed.sec.secbuf_base;
	dvbdmxfeed->feed.sec.secbufp = 0;
	dvbdmxfeed->feed.sec.seclen = 0;
	dvbdmxfeed->pusi_seen[0] = false;

	if (!dvbdmx->start_feed) {
		mutex_unlock(&dvbdmx->mutex);
		return -ENODEV;
	}

	prepare_secfilters(dvbdmxfeed);

	if ((ret = dvbdmx->start_feed(dvbdmxfeed)) < 0) {
		mutex_unlock(&dvbdmx->mutex);
		return ret;
	}

	spin_lock_irq(&dvbdmx->lock);
	feed->is_filtering = 1;
	dvbdmxfeed->state = DMX_STATE_GO;
	spin_unlock_irq(&dvbdmx->lock);

	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dmx_ip_section_feed_start_filtering(struct dmx_ip_section_feed *feed)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	int ret;
	int i = 0;

	if (mutex_lock_interruptible(&dvbdmx->mutex))
		return -ERESTARTSYS;

	if(!feed->runtime_pid_change) {
		if (feed->is_filtering) {
			mutex_unlock(&dvbdmx->mutex);
			return -EBUSY;
		}
	}
	
	if (!dvbdmxfeed->filter) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}

	if(!feed->runtime_pid_change) {
		for (i = 0; i < MAX_NUMBER_OF_PID; i++) {
			dvbdmxfeed->feed.ip_sec.tsfeedp[i] = 0;
			dvbdmxfeed->feed.ip_sec.secbuf[i] =
				*(dvbdmxfeed->feed.ip_sec.secbuf_base + i);
			dvbdmxfeed->feed.ip_sec.secbufp[i] = 0;
			dvbdmxfeed->feed.ip_sec.seclen[i] = 0;
		}
	}

	if (!dvbdmx->start_feed) {
		mutex_unlock(&dvbdmx->mutex);
		return -ENODEV;
	}

	prepare_ip_secfilters(dvbdmxfeed);

	ret = dvbdmx->start_feed(dvbdmxfeed);
	if (ret < 0) {
		mutex_unlock(&dvbdmx->mutex);
		return ret;
	}

	spin_lock_irq(&dvbdmx->lock);
	feed->is_filtering = 1;
	dvbdmxfeed->state = DMX_STATE_GO;
	spin_unlock_irq(&dvbdmx->lock);

	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dmx_section_feed_stop_filtering(struct dmx_section_feed *feed)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	int ret;

	mutex_lock(&dvbdmx->mutex);

	if (!dvbdmx->stop_feed) {
		mutex_unlock(&dvbdmx->mutex);
		return -ENODEV;
	}

	ret = dvbdmx->stop_feed(dvbdmxfeed);

	spin_lock_irq(&dvbdmx->lock);
	dvbdmxfeed->state = DMX_STATE_READY;
	feed->is_filtering = 0;
	spin_unlock_irq(&dvbdmx->lock);

	mutex_unlock(&dvbdmx->mutex);
	return ret;
}

static int dmx_ip_section_feed_stop_filtering(struct dmx_ip_section_feed *feed)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	int ret;

	mutex_lock(&dvbdmx->mutex);

	if (!dvbdmx->stop_feed) {
		mutex_unlock(&dvbdmx->mutex);
		return -ENODEV;
	}

	ret = dvbdmx->stop_feed(dvbdmxfeed);

	spin_lock_irq(&dvbdmx->lock);
	dvbdmxfeed->state = DMX_STATE_READY;
	feed->is_filtering = 0;
	spin_unlock_irq(&dvbdmx->lock);

	mutex_unlock(&dvbdmx->mutex);
	return ret;
}

static int dmx_section_feed_release_filter(struct dmx_section_feed *feed,
					   struct dmx_section_filter *filter)
{
	struct dvb_demux_filter *dvbdmxfilter = (struct dvb_demux_filter *)filter, *f;
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;

	mutex_lock(&dvbdmx->mutex);

	if (dvbdmxfilter->feed != dvbdmxfeed) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}

	if (feed->is_filtering) {
		/* release dvbdmx->mutex as far as it is
		   acquired by stop_filtering() itself */
		mutex_unlock(&dvbdmx->mutex);
		feed->stop_filtering(feed);
		mutex_lock(&dvbdmx->mutex);
	}

	spin_lock_irq(&dvbdmx->lock);
	f = dvbdmxfeed->filter;

	if (f == dvbdmxfilter) {
		dvbdmxfeed->filter = dvbdmxfilter->next;
	} else {
		while (f->next != dvbdmxfilter)
			f = f->next;
		f->next = f->next->next;
	}

	dvbdmxfilter->state = DMX_STATE_FREE;
	spin_unlock_irq(&dvbdmx->lock);
	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dmx_ip_section_feed_release_filter(struct dmx_ip_section_feed *feed,
		struct dmx_ip_section_filter *filter)
{
	struct dvb_demux_filter *dvbdmxfilter = container_of(filter,
			struct dvb_demux_filter, ip_filter), *f;

	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;

	mutex_lock(&dvbdmx->mutex);

	if (dvbdmxfilter->feed != dvbdmxfeed) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}

	if(!feed->runtime_pid_change) {
		if (feed->is_filtering)
			feed->stop_filtering(feed);
	}
	spin_lock_irq(&dvbdmx->lock);
	f = dvbdmxfeed->filter;

	if (f == dvbdmxfilter) {
		dvbdmxfeed->filter = dvbdmxfilter->next;
	} else {
		while (f->next != dvbdmxfilter)
			f = f->next;
		f->next = f->next->next;
	}
	dvbdmxfilter->state = DMX_STATE_FREE;
	spin_unlock_irq(&dvbdmx->lock);
	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dmx_gse_feed_release_filter(struct dmx_gse_feed *feed,
				struct dmx_gsesection_filter *filter)
{
	struct dvb_demux_filter *dvbdmxfilter = container_of(filter,
			struct dvb_demux_filter, gsefilter), *f;
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;

	mutex_lock(&dvbdmx->mutex);

	if (dvbdmxfilter->feed != dvbdmxfeed) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}

	if (feed->is_filtering)
		feed->stop_filtering(feed, NULL);

	spin_lock_irq(&dvbdmx->lock);
	f = dvbdmxfeed->filter;

	if (f == dvbdmxfilter) {
		dvbdmxfeed->filter = dvbdmxfilter->next;
	} else {
		while (f->next != dvbdmxfilter)
			f = f->next;
		f->next = f->next->next;
	}
	dvbdmxfilter->state = DMX_STATE_FREE;
	spin_unlock_irq(&dvbdmx->lock);
	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dmx_gse_feed_release_labelfilter(struct dmx_gse_feed *feed,
					   struct dmx_gselabel_filter *filter)
{
	struct dvb_demux_filter *dvbdmxfilter = (struct dvb_demux_filter *)filter, *f;
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;

	mutex_lock(&dvbdmx->mutex);

	if (dvbdmxfilter->feed != dvbdmxfeed) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}

	if (feed->is_filtering)
		feed->stop_filtering(feed,NULL);

	spin_lock_irq(&dvbdmx->lock);
	f = dvbdmxfeed->filter;

	if (f == dvbdmxfilter) {
		dvbdmxfeed->filter = dvbdmxfilter->next;
	} else {
		while (f->next != dvbdmxfilter)
			f = f->next;
		f->next = f->next->next;
	}
	dvbdmxfilter->state = DMX_STATE_FREE;
	spin_unlock_irq(&dvbdmx->lock);
	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dvbdmx_allocate_section_feed(struct dmx_demux *demux,
					struct dmx_section_feed **feed,
					dmx_section_cb callback)
{
	struct dvb_demux *dvbdmx = (struct dvb_demux *)demux;
	struct dvb_demux_feed *dvbdmxfeed;

	if (mutex_lock_interruptible(&dvbdmx->mutex))
		return -ERESTARTSYS;

	if (!(dvbdmxfeed = dvb_dmx_feed_alloc(dvbdmx))) {
		mutex_unlock(&dvbdmx->mutex);
		return -EBUSY;
	}

	dvbdmxfeed->type = DMX_TYPE_SEC;
	dvbdmxfeed->cb.sec = callback;
	dvbdmxfeed->demux = dvbdmx;
	dvbdmxfeed->pid = 0xffff;
	dvbdmxfeed->buffer_flags = 0;
	dvbdmxfeed->feed.sec.secbuf = dvbdmxfeed->feed.sec.secbuf_base;
	dvbdmxfeed->feed.sec.secbufp = dvbdmxfeed->feed.sec.seclen = 0;
	dvbdmxfeed->feed.sec.tsfeedp = 0;
	dvbdmxfeed->filter = NULL;

	(*feed) = &dvbdmxfeed->feed.sec;
	(*feed)->is_filtering = 0;
	(*feed)->parent = demux;
	(*feed)->priv = NULL;

	(*feed)->set = dmx_section_feed_set;
	(*feed)->allocate_filter = dmx_section_feed_allocate_filter;
	(*feed)->start_filtering = dmx_section_feed_start_filtering;
	(*feed)->stop_filtering = dmx_section_feed_stop_filtering;
	(*feed)->release_filter = dmx_section_feed_release_filter;

	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dvbdmx_allocate_ip_section_feed(struct dmx_demux *demux,
					struct dmx_ip_section_feed **feed,
					dmx_ip_section_cb callback)
{
	struct dvb_demux *dvbdmx = (struct dvb_demux *)demux;
	struct dvb_demux_feed *dvbdmxfeed;
	int i = 0;

	if (mutex_lock_interruptible(&dvbdmx->mutex))
		return -ERESTARTSYS;

	dvbdmxfeed = dvb_dmx_feed_alloc(dvbdmx);
	if (!dvbdmxfeed) {
		mutex_unlock(&dvbdmx->mutex);
		return -EBUSY;
	}

	dvbdmxfeed->type = DMX_TYPE_IP_SEC;
	dvbdmxfeed->cb.ip_sec = callback;
	dvbdmxfeed->demux = dvbdmx;
	dvbdmxfeed->pid = 0xffff;

	for (i = 0; i < MAX_NUMBER_OF_PID; i++) {
		dvbdmxfeed->feed.ip_sec.secbuf[i] =
		*(dvbdmxfeed->feed.ip_sec.secbuf_base + i);
		dvbdmxfeed->feed.ip_sec.secbufp[i] =
			dvbdmxfeed->feed.ip_sec.seclen[i] = 0;
		dvbdmxfeed->feed.ip_sec.tsfeedp[i] = 0;
	}
	dvbdmxfeed->filter = NULL;
	dvbdmxfeed->ip_pid_index = 0;

	(*feed) = &dvbdmxfeed->feed.ip_sec;
	(*feed)->is_filtering = 0;
	(*feed)->parent = demux;
	(*feed)->priv = NULL;
	(*feed)->runtime_pid_change = 0;

	(*feed)->set = dmx_ip_section_feed_set;
	(*feed)->allocate_ip_filter = dmx_ip_section_feed_allocate_filter;
	(*feed)->start_filtering = dmx_ip_section_feed_start_filtering;
	(*feed)->stop_filtering = dmx_ip_section_feed_stop_filtering;
	(*feed)->release_ip_filter = dmx_ip_section_feed_release_filter;

	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dvbdmx_release_section_feed(struct dmx_demux *demux,
				       struct dmx_section_feed *feed)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = (struct dvb_demux *)demux;

	mutex_lock(&dvbdmx->mutex);

	if (dvbdmxfeed->state == DMX_STATE_FREE) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}
	dvbdmxfeed->state = DMX_STATE_FREE;

	dvb_demux_feed_del(dvbdmxfeed);

	dvbdmxfeed->pid = 0xffff;

	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

static int dvbdmx_release_ip_section_feed(struct dmx_demux *demux,
		struct dmx_ip_section_feed *feed)
{
	struct dvb_demux_feed *dvbdmxfeed = (struct dvb_demux_feed *)feed;
	struct dvb_demux *dvbdmx = (struct dvb_demux *)demux;

	mutex_lock(&dvbdmx->mutex);

	if (dvbdmxfeed->state == DMX_STATE_FREE) {
		mutex_unlock(&dvbdmx->mutex);
		return -EINVAL;
	}
	dvbdmxfeed->state = DMX_STATE_FREE;

	dvb_demux_feed_del(dvbdmxfeed);

	feed->runtime_pid_change = 0;
	memset(&dvbdmxfeed->ip_new_pid[0], 0xffff,
		sizeof(u16) * MAX_NUMBER_OF_PID); 	
	memset(&dvbdmxfeed->ip_pid[0], 0xffff, sizeof(u16) * MAX_NUMBER_OF_PID);


	mutex_unlock(&dvbdmx->mutex);
	return 0;
}

/******************************************************************************
* dmx_gse_feed calls
******************************************************************************/

static int dmx_gse_feed_set(struct dmx_gse_feed *gse_feed,int mode,int payload_type,
	int protocol_type,int check_crc)
{
	struct dvb_demux_feed *feed = (struct dvb_demux_feed*) gse_feed;
	struct dvb_demux *demux = feed->demux;

	if ((mode < 0)||(mode > DMX_GSE_SI))
		return -EINVAL;

	feed->gse.type = mode;
	feed->gse.gse_payload_type = payload_type;
	feed->feed.gse.check_crc = check_crc;
	feed->gse.protocol_type = protocol_type;
	feed->state = DMX_STATE_READY;
	if (mutex_lock_interruptible(&demux->mutex))
		return -ERESTARTSYS;
	dvb_demux_feed_add(feed);
	mutex_unlock(&demux->mutex);
	return 0;
}

static int dmx_gse_feed_start_filtering(struct dmx_gse_feed *gse_feed,unsigned char *mac)
{
	struct dvb_demux_feed *feed = (struct dvb_demux_feed *)gse_feed;
	struct dvb_demux *demux = feed->demux;
	int ret;

	if (mutex_lock_interruptible(&demux->mutex))
		return -ERESTARTSYS;

	if (feed->state != DMX_STATE_READY || feed->type != DMX_TYPE_GSE) {
		mutex_unlock(&demux->mutex);
		return -EINVAL;
	}

	if (!demux->start_feed) {
		mutex_unlock(&demux->mutex);
		return -ENODEV;
	}

	feed->feed.gse.mac = mac;

	if ((ret = demux->start_feed(feed)) < 0) {
		mutex_unlock(&demux->mutex);
		return ret;
	}

	if(feed->gse.type == DMX_GSE_SI)
	prepare_gsesecfilters(feed);

	spin_lock_irq(&demux->lock);
	gse_feed->is_filtering = 1;
	feed->state = DMX_STATE_GO;
	spin_unlock_irq(&demux->lock);
	mutex_unlock(&demux->mutex);

	return 0;
}

static int dmx_gse_feed_stop_filtering(struct dmx_gse_feed *gse_feed,unsigned char *mac)
{
	struct dvb_demux_feed *feed = (struct dvb_demux_feed *)gse_feed;
	struct dvb_demux *demux = feed->demux;
	int ret;

	mutex_lock(&demux->mutex);

	if (feed->state < DMX_STATE_GO) {
		mutex_unlock(&demux->mutex);
		return -EINVAL;
	}

        feed->feed.gse.mac = mac;

	if (!demux->stop_feed) {
		mutex_unlock(&demux->mutex);
		return -ENODEV;
	}

	ret = demux->stop_feed(feed);

	spin_lock_irq(&demux->lock);
	gse_feed->is_filtering = 0;
	feed->state = DMX_STATE_READY;
	spin_unlock_irq(&demux->lock);
	mutex_unlock(&demux->mutex);

	return ret;
}

static int dvbdmx_allocate_gse_feed(struct dmx_demux *dmx, struct dmx_gse_feed **gse_feed,
	dmx_gse_cb gse_callback, dmx_gse_section_cb sec_callback)
{
	struct dvb_demux *demux = (struct dvb_demux *)dmx;
	struct dvb_demux_feed *feed;

	dprintk("dmx=%p, gse_feed=%p \n", dmx, gse_feed);

	if (mutex_lock_interruptible(&demux->mutex))
		return -ERESTARTSYS;

	if (!(feed = dvb_dmx_feed_alloc(demux))) {
		mutex_unlock(&demux->mutex);
		return -EBUSY;
	}
	feed->type = DMX_TYPE_GSE;

	if(gse_callback !=NULL)
		feed->cb.gse = gse_callback;
	else
		feed->cb.gse_sec = sec_callback;

	feed->demux = demux;
	feed->gse.type = DMX_GSE_PDU;
	feed->filter = NULL;
	*gse_feed = &feed->feed.gse;
	(*gse_feed)->parent = dmx;
	(*gse_feed)->priv = NULL;
	(*gse_feed)->is_filtering = 0;
	(*gse_feed)->allocate_filter = dmx_gse_feed_allocate_secfilter;
	(*gse_feed)->allocate_labelfilter = dmx_gse_feed_allocate_labelfilter;
	(*gse_feed)->start_filtering = dmx_gse_feed_start_filtering;
	(*gse_feed)->stop_filtering = dmx_gse_feed_stop_filtering;
	(*gse_feed)->set = dmx_gse_feed_set;
	(*gse_feed)->release_filter = dmx_gse_feed_release_filter;
	(*gse_feed)->release_labelfilter = dmx_gse_feed_release_labelfilter;
	mutex_unlock(&demux->mutex);
	return 0;
}

static int dvbdmx_release_gse_feed(struct dmx_demux *dmx, struct dmx_gse_feed *gse_feed)
{
	struct dvb_demux *demux = (struct dvb_demux *)dmx;
	struct dvb_demux_feed *feed = (struct dvb_demux_feed*) gse_feed;

	dprintk("dmx=%p, gse_feed=%p\n", dmx, gse_feed);

	mutex_lock(&demux->mutex);

	if (feed->state == DMX_STATE_FREE) {
		mutex_unlock(&demux->mutex);
		return -EINVAL;
	}

	feed->state = DMX_STATE_FREE;

	dvb_demux_feed_del(feed);

	mutex_unlock(&demux->mutex);
	return 0;
}

/******************************************************************************
 * dvb_demux kernel data API calls
 ******************************************************************************/

static int dvbdmx_open(struct dmx_demux *demux)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;

	if (dvbdemux->users >= MAX_DVB_DEMUX_USERS)
		return -EUSERS;

	dvbdemux->users++;
	return 0;
}

static int dvbdmx_close(struct dmx_demux *demux)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;

	if (dvbdemux->users == 0)
		return -ENODEV;

	dvbdemux->users--;
	//FIXME: release any unneeded resources if users==0
	return 0;
}

static int dvbdmx_write(struct dmx_demux *demux, const char __user *buf, size_t count)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;
	void *p;

	if ((!demux->frontend) || (demux->frontend->source != DMX_MEMORY_FE))
		return -EINVAL;

	p = memdup_user(buf, count);
	if (IS_ERR(p))
		return PTR_ERR(p);
	if (mutex_lock_interruptible(&dvbdemux->mutex)) {
		kfree(p);
		return -ERESTARTSYS;
	}
	dvb_dmx_swfilter(dvbdemux, p, count);
	kfree(p);
	mutex_unlock(&dvbdemux->mutex);

	if (signal_pending(current))
		return -EINTR;
	return count;
}

static int dvbdmx_write_gse(struct dmx_demux *demux, const char __user *buf,
				size_t count)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;
	void *p;

	if ((!demux->frontend) || (demux->frontend->source != DMX_MEMORY_FE))
		return -EINVAL;

	p = memdup_user(buf, count);
	if (IS_ERR(p))
		return PTR_ERR(p);

	if (mutex_lock_interruptible(&dvbdemux->mutex)) {
		kfree(p);
		return -ERESTARTSYS;
	}

	dvb_dmx_swfilter_gse(dvbdemux, p, count);

	kfree(p);
	mutex_unlock(&dvbdemux->mutex);

	if (signal_pending(current))
		return -EINTR;
	return count;
}

static int dvbdmx_add_frontend(struct dmx_demux *demux,
			       struct dmx_frontend *frontend)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;
	struct list_head *head = &dvbdemux->frontend_list;

	list_add(&(frontend->connectivity_list), head);

	return 0;
}

static int dvbdmx_remove_frontend(struct dmx_demux *demux,
				  struct dmx_frontend *frontend)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;
	struct list_head *pos, *n, *head = &dvbdemux->frontend_list;

	list_for_each_safe(pos, n, head) {
		if (DMX_FE_ENTRY(pos) == frontend) {
			list_del(pos);
			return 0;
		}
	}

	return -ENODEV;
}

static struct list_head *dvbdmx_get_frontends(struct dmx_demux *demux)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;

	if (list_empty(&dvbdemux->frontend_list))
		return NULL;

	return &dvbdemux->frontend_list;
}

static int dvbdmx_connect_frontend(struct dmx_demux *demux,
				   struct dmx_frontend *frontend)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;

	if (demux->frontend)
		return -EINVAL;

	mutex_lock(&dvbdemux->mutex);

	demux->frontend = frontend;
	mutex_unlock(&dvbdemux->mutex);
	return 0;
}

static int dvbdmx_disconnect_frontend(struct dmx_demux *demux)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;

	mutex_lock(&dvbdemux->mutex);

	demux->frontend = NULL;
	mutex_unlock(&dvbdemux->mutex);
	return 0;
}

static int dvbdmx_get_pes_pids(struct dmx_demux *demux, u16 * pids)
{
	struct dvb_demux *dvbdemux = (struct dvb_demux *)demux;

	memcpy(pids, dvbdemux->pids, 5 * sizeof(u16));
	return 0;
}

int dvb_dmx_init(struct dvb_demux *dvbdemux)
{
	int i;
	struct dmx_demux *dmx = &dvbdemux->dmx;

	dvbdemux->cnt_storage = NULL;
	dvbdemux->users = 0;
	dvbdemux->filter = vmalloc(array_size(sizeof(struct dvb_demux_filter),
					      dvbdemux->filternum));

	if (!dvbdemux->filter)
		return -ENOMEM;

	dvbdemux->feed = vmalloc(array_size(sizeof(struct dvb_demux_feed),
					    dvbdemux->feednum));
	if (!dvbdemux->feed) {
		vfree(dvbdemux->filter);
		dvbdemux->filter = NULL;
		return -ENOMEM;
	}
	for (i = 0; i < dvbdemux->filternum; i++) {
		dvbdemux->filter[i].state = DMX_STATE_FREE;
		dvbdemux->filter[i].index = i;
	}
	for (i = 0; i < dvbdemux->feednum; i++) {
		dvbdemux->feed[i].state = DMX_STATE_FREE;
		dvbdemux->feed[i].index = i;
	}

	dvbdemux->cnt_storage = vmalloc(MAX_PID + 1);
	if (!dvbdemux->cnt_storage)
		pr_warn("Couldn't allocate memory for TS/TEI check. Disabling it\n");

	INIT_LIST_HEAD(&dvbdemux->frontend_list);

	for (i = 0; i < DMX_PES_OTHER; i++) {
		dvbdemux->pesfilter[i] = NULL;
		dvbdemux->pids[i] = 0xffff;
	}

	INIT_LIST_HEAD(&dvbdemux->feed_list);
	INIT_LIST_HEAD(&dvbdemux->gse_buff_list);

	dvbdemux->playing = 0;
	dvbdemux->recording = 0;
	dvbdemux->tsbufp = 0;

	if (!dvbdemux->check_crc32)
		dvbdemux->check_crc32 = dvb_dmx_crc32;

	if (!dvbdemux->memcopy)
		dvbdemux->memcopy = dvb_dmx_memcopy;

	dmx->frontend = NULL;
	dmx->priv = dvbdemux;
	dmx->open = dvbdmx_open;
	dmx->close = dvbdmx_close;
	dmx->write = dvbdmx_write;
	dmx->write_gse = dvbdmx_write_gse;
	dmx->allocate_ts_feed = dvbdmx_allocate_ts_feed;
	dmx->release_ts_feed = dvbdmx_release_ts_feed;
	dmx->allocate_section_feed = dvbdmx_allocate_section_feed;
	dmx->release_section_feed = dvbdmx_release_section_feed;
	dmx->allocate_ip_section_feed = dvbdmx_allocate_ip_section_feed;
	dmx->release_ip_section_feed = dvbdmx_release_ip_section_feed;
	dmx->allocate_gse_feed = dvbdmx_allocate_gse_feed;
	dmx->release_gse_feed = dvbdmx_release_gse_feed;

	dmx->add_frontend = dvbdmx_add_frontend;
	dmx->remove_frontend = dvbdmx_remove_frontend;
	dmx->get_frontends = dvbdmx_get_frontends;
	dmx->connect_frontend = dvbdmx_connect_frontend;
	dmx->disconnect_frontend = dvbdmx_disconnect_frontend;
	dmx->get_pes_pids = dvbdmx_get_pes_pids;

	mutex_init(&dvbdemux->mutex);
	spin_lock_init(&dvbdemux->lock);

	return 0;
}

EXPORT_SYMBOL(dvb_dmx_init);

void dvb_dmx_release(struct dvb_demux *dvbdemux)
{
	vfree(dvbdemux->cnt_storage);
	vfree(dvbdemux->filter);
	vfree(dvbdemux->feed);
}

EXPORT_SYMBOL(dvb_dmx_release);
