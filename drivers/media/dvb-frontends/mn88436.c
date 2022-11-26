
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <media/dvb_frontend.h>
#include "MN_DMD_API.h"
#include "MXL603_API.h"
#include "mn88436.h"



DMD_u8_t DMD_REG_ATSC[]={
0		,0x0		,0x50		,
0		,0x1		,0x0		,
0		,0x2		,0xC0		,
0		,0x3		,0x0		,
0		,0x4		,0x0		,
0		,0x5		,0x0		,
0		,0x6		,0x0		,
0		,0x7		,0x0		,
0		,0x8		,0x0		,
0		,0x9		,0x0		,
0		,0xA		,0x1E		,
0		,0xB		,0x35		,
0		,0xC		,0x56		,
0		,0xD		,0x8E		,
0		,0xE		,0xB9		,
0		,0xF		,0x72		,
0		,0x10		,0x0		,
0		,0x11		,0x14		,
0		,0x12		,0xE3		,
0		,0x13		,0x4E		,
0		,0x14		,0x8		,
0		,0x15		,0x5		,
0		,0x16		,0x63		,
0		,0x17		,0x0		,
0		,0x18		,0x0		,
0		,0x19		,0x0		,
0		,0x1A		,0x0		,
0		,0x1B		,0x0		,
0		,0x1C		,0x0		,
0		,0x1D		,0x0		,
0		,0x1E		,0x0		,
0		,0x1F		,0x0		,
0		,0x20		,0x0		,
0		,0x21		,0x50		,
0		,0x22		,0x60		,
0		,0x23		,0x36		,
0		,0x24		,0x2		,
0		,0x25		,0x0		,
0		,0x26		,0x0		,
0		,0x27		,0x0		,
0		,0x28		,0x0		,
0		,0x29		,0x0		,
0		,0x2A		,0x20		,
0		,0x2B		,0xC0		,
0		,0x2C		,0x23		,
0		,0x2D		,0x3F		,
0		,0x2E		,0x3F		,
0		,0x2F		,0x0		,
0		,0x30		,0x2E		,
0		,0x31		,0x0		,
0		,0x32		,0x0		,
0		,0x33		,0x81		,
0		,0x34		,0x0		,
0		,0x35		,0x26		,
0		,0x36		,0x21		,
0		,0x37		,0x88		,
0		,0x38		,0x3		,
0		,0x39		,0x19		,
0		,0x3A		,0x85		,
0		,0x3B		,0x5		,
0		,0x3C		,0xC9		,
0		,0x3D		,0x2		,
0		,0x3E		,0x30		,
0		,0x3F		,0x69		,
0		,0x40		,0x1F		,
0		,0x41		,0xF0		,
0		,0x42		,0x0		,
0		,0x43		,0x96		,
0		,0x44		,0x72		,
0		,0x45		,0x1B		,
0		,0x46		,0x2D		,
0		,0x47		,0x1A		,
0		,0x48		,0x31		,
0		,0x49		,0xFE		,
0		,0x4A		,0x96		,
0		,0x4B		,0x7		,
0		,0x4C		,0x26		,
0		,0x4D		,0xE3		,
0		,0x4E		,0x22		,
0		,0x4F		,0x1B		,
0		,0x50		,0x26		,
0		,0x51		,0x12		,
0		,0x52		,0x40		,
0		,0x53		,0x50		,
0		,0x54		,0x60		,
0		,0x55		,0x40		,
0		,0x56		,0xED		,
0		,0x57		,0x96		,
0		,0x58		,0x4A		,
0		,0x59		,0xDE		,
0		,0x5A		,0x88		,
0		,0x5B		,0xC8		,
0		,0x5C		,0x2D		,
0		,0x5D		,0x1		,
0		,0x5E		,0x0		,
0		,0x5F		,0xB8		,
0		,0x60		,0x40		,
0		,0x61		,0x14		,
0		,0x62		,0x13		,
0		,0x63		,0x30		,
0		,0x64		,0x59		,
0		,0x65		,0x7		,
0		,0x66		,0xF0		,
0		,0x67		,0x47		,
0		,0x68		,0xA1		,
0		,0x69		,0x80		,
0		,0x6A		,0x0		,
0		,0x6B		,0x0		,
0		,0x6C		,0xC0		,
0		,0x6D		,0x0		,
0		,0x6E		,0x0		,
0		,0x6F		,0x0		,
0		,0x70		,0x0		,
0		,0x71		,0x0		,
0		,0x72		,0x0		,
0		,0x73		,0x0		,
0		,0x74		,0x2F		,
0		,0x75		,0x0		,
0		,0x76		,0x0		,
0		,0x77		,0x0		,
0		,0x78		,0x0		,
0		,0x79		,0x40		,
0		,0x7A		,0x20		,
0		,0x7B		,0x40		,
0		,0x7C		,0x80		,
0		,0x7D		,0xFF		,
0		,0x7E		,0x20		,
0		,0x7F		,0x40		,
0		,0x80		,0x10		,
0		,0x81		,0x0		,
0		,0x82		,0xE5		,
0		,0x83		,0xC4		,
0		,0x84		,0xE9		,
0		,0x85		,0x52		,
0		,0x86		,0x5F		,
0		,0x87		,0x53		,
0		,0x88		,0x20		,
0		,0x89		,0x43		,
0		,0x8A		,0x11		,
0		,0x8B		,0x8		,
0		,0x8C		,0x43		,
0		,0x8D		,0x11		,
0		,0x8E		,0x8		,
0		,0x8F		,0x0		,
0		,0x90		,0x60		,
0		,0x91		,0x5B		,
0		,0x92		,0x80		,
0		,0x93		,0xE4		,
0		,0x94		,0x34		,
0		,0x95		,0x0		,
0		,0x96		,0x0		,
0		,0x97		,0x7		,
0		,0x98		,0x0		,
0		,0x99		,0xB0		,
0		,0x9A		,0x68		,
0		,0x9B		,0x50		,
0		,0x9C		,0x84		,
0		,0x9D		,0xA9		,
0		,0x9E		,0x11		,
0		,0x9F		,0x4		,
0		,0xA0		,0x44		,
0		,0xA1		,0x14		,
0		,0xA2		,0x9C		,
0		,0xA3		,0x15		,
0		,0xA4		,0xF6		,
0		,0xA5		,0x36		,
0		,0xA6		,0x16		,
0		,0xA7		,0x3F		,
0		,0xA8		,0x1		,
0		,0xA9		,0x8		,
0		,0xAA		,0x0		,
0		,0xAB		,0x0		,
0		,0xAC		,0x0		,
0		,0xAD		,0x65		,
0		,0xAE		,0x87		,
0		,0xAF		,0x56		,
0		,0xB0		,0x52		,
0		,0xB1		,0x55		,
0		,0xB2		,0x35		,
0		,0xB3		,0x13		,
0		,0xB4		,0x88		,
0		,0xB5		,0x23		,
0		,0xB6		,0x28		,
0		,0xB7		,0x3C		,
0		,0xB8		,0x1		,
0		,0xB9		,0x5B		,
0		,0xBA		,0x0		,
0		,0xBB		,0x0		,
0		,0xBC		,0x0		,
0		,0xBD		,0x0		,
0		,0xBE		,0x0		,
0		,0xBF		,0x0		,
0		,0xC0		,0x0		,
0		,0xC1		,0x0		,
0		,0xC2		,0x0		,
0		,0xC3		,0x0		,
0		,0xC4		,0x0		,
0		,0xC5		,0x0		,
0		,0xC6		,0x0		,
0		,0xC7		,0x0		,
0		,0xC8		,0x0		,
0		,0xC9		,0x0		,
0		,0xCA		,0x0		,
0		,0xCB		,0x0		,
0		,0xCC		,0x0		,
0		,0xCD		,0x0		,
0		,0xCE		,0x0		,
0		,0xCF		,0x0		,
0		,0xD0		,0x0		,
0		,0xD1		,0x0		,
0		,0xD2		,0x0		,
0		,0xD3		,0x0		,
0		,0xD4		,0x0		,
0		,0xD5		,0x0		,
0		,0xD6		,0x0		,
0		,0xD7		,0x0		,
0		,0xD8		,0x0		,
0		,0xD9		,0xA0		,
0		,0xDA		,0x0		,
0		,0xDB		,0x0		,
0		,0xDC		,0x0		,
0		,0xDD		,0x0		,
0		,0xDE		,0x0		,
0		,0xDF		,0x9		,
0		,0xE0		,0x8		,
0		,0xE1		,0x8		,
0		,0xE2		,0xA8		,
0		,0xE3		,0x0		,
0		,0xE4		,0x0		,
0		,0xE5		,0x0		,
0		,0xE6		,0x0		,
0		,0xE7		,0xB4		,
0		,0xE8		,0xA		,
0		,0xE9		,0x0		,
0		,0xEA		,0x0		,
0		,0xEB		,0x0		,
0		,0xEC		,0x0		,
0		,0xED		,0x0		,
0		,0xEE		,0x0		,
0		,0xEF		,0xB4		,
0		,0xF0		,0x91		,
0		,0xF1		,0x0		,
0		,0xF2		,0x0		,
0		,0xF3		,0x0		,
0		,0xF4		,0x0		,
0		,0xF5		,0x0		,
0		,0xF6		,0x0		,
0		,0xF7		,0x0		,
0		,0xF8		,0x0		,
0		,0xF9		,0x0		,
0		,0xFA		,0x0		,
0		,0xFB		,0x80		,
0		,0xFC		,0x10		,
0		,0xFD		,0x2		,
0		,0xFE		,0x20		,
0		,0xFF		,0xAA		,
1		,0x9		,0x0		,
1		,0xA		,0x0		,
1		,0xB		,0x0		,
1		,0xC		,0x8		,
1		,0xD		,0x0		,
1		,0x14		,0x8		,
1		,0x5A		,0x3C		,
1		,0x5B		,0x0		,
1		,0x5C		,0x0		,
1		,0x5D		,0x0		,
1		,0x5E		,0x0		,
1		,0x5F		,0x0		,
1		,0x60		,0x0		,
1		,0x61		,0xAC		,
1		,0x62		,0x24		,
1		,0x63		,0x0		,
1		,0x64		,0x0		,
1		,0x65		,0x0		,
1		,0x66		,0x0		,
1		,0x67		,0x0		,
1		,0x68		,0x0		,
1		,0x69		,0x0		,
1		,0x6A		,0x0		,
1		,0x6B		,0x0		,
1		,0x74		,0x0		,
1		,0x79		,0x0		,
1		,0x80		,0x5		,
1		,0x81		,0x0		,
1		,0x82		,0x40		,
1		,0x83		,0x0		,
1		,0x84		,0x40		,
1		,0x85		,0x37		,
1		,0x86		,0x2		,
1		,0x87		,0x20		,
1		,0x88		,0x0		,
1		,0x89		,0x20		,
1		,0x8A		,0x0		,
1		,0x8B		,0x3		,
1		,0x8C		,0x60		,
1		,0x8D		,0x30		,
1		,0x8E		,0x88		,
1		,0x8F		,0x11		,
1		,0x90		,0x0		,
1		,0x91		,0x0		,
1		,0x92		,0x76		,
1		,0x93		,0xA6		,
1		,0x94		,0x19		,
1		,0x95		,0x52		,
1		,0x96		,0x73		,
1		,0x97		,0x96		,
1		,0x98		,0x9E		,
1		,0x99		,0x69		,
1		,0x9A		,0xFA		,
1		,0x9B		,0x8F		,
1		,0x9C		,0x2E		,
1		,0x9D		,0x8E		,
1		,0x9E		,0x0		,
1		,0x9F		,0x0		,
1		,0xA0		,0xFD		,
1		,0xA1		,0x6D		,
1		,0xA2		,0x63		,
1		,0xA3		,0x52		,
1		,0xFF		,0x55		,
0xff,0xff,0xff};

// Mode : QAM_B_64QAM
DMD_u8_t DMD_REG_QAM_B_64QAM[]={
0		,0x0		,0x51		,
0		,0x1		,0x0		,
0		,0x2		,0xC0		,
0		,0x3		,0x0		,
0		,0x4		,0x0		,
0		,0x5		,0x0		,
0		,0x6		,0x0		,
0		,0x7		,0x0		,
0		,0x8		,0x0		,
0		,0x9		,0x0		,
0		,0xA		,0x16		,
0		,0xB		,0x35		,
0		,0xC		,0x56		,
0		,0xD		,0x97		,
0		,0xE		,0xDE		,
0		,0xF		,0xD8		,
0		,0x10		,0x0		,
0		,0x11		,0x14		,
0		,0x12		,0xE4		,
0		,0x13		,0x74		,
0		,0x14		,0x8		,
0		,0x15		,0x5		,
0		,0x16		,0x63		,
0		,0x17		,0x0		,
0		,0x18		,0x0		,
0		,0x19		,0x0		,
0		,0x1A		,0x0		,
0		,0x1B		,0x0		,
0		,0x1C		,0x0		,
0		,0x1D		,0x0		,
0		,0x1E		,0x0		,
0		,0x1F		,0x0		,
0		,0x20		,0x0		,
0		,0x21		,0x50		,
0		,0x22		,0x60		,
0		,0x23		,0x36		,
0		,0x24		,0x2		,
0		,0x25		,0x0		,
0		,0x26		,0x0		,
0		,0x27		,0x0		,
0		,0x28		,0x0		,
0		,0x29		,0x0		,
0		,0x2A		,0x20		,
0		,0x2B		,0xC0		,
0		,0x2C		,0x23		,
0		,0x2D		,0x3F		,
0		,0x2E		,0x3F		,
0		,0x2F		,0x0		,
0		,0x30		,0x2E		,
0		,0x31		,0x0		,
0		,0x32		,0x0		,
0		,0x33		,0x81		,
0		,0x34		,0x0		,
0		,0x35		,0x26		,
0		,0x36		,0x21		,
0		,0x37		,0x88		,
0		,0x38		,0x3		,
0		,0x39		,0x19		,
0		,0x3A		,0x85		,
0		,0x3B		,0x5		,
0		,0x3C		,0xC9		,
0		,0x3D		,0x2		,
0		,0x3E		,0x30		,
0		,0x3F		,0x69		,
0		,0x40		,0x1F		,
0		,0x41		,0xF0		,
0		,0x42		,0x0		,
0		,0x43		,0x96		,
0		,0x44		,0x72		,
0		,0x45		,0x1B		,
0		,0x46		,0x2D		,
0		,0x47		,0x1A		,
0		,0x48		,0x31		,
0		,0x49		,0xFE		,
0		,0x4A		,0x96		,
0		,0x4B		,0x7		,
0		,0x4C		,0x26		,
0		,0x4D		,0xE3		,
0		,0x4E		,0x22		,
0		,0x4F		,0x1B		,
0		,0x50		,0x26		,
0		,0x51		,0x12		,
0		,0x52		,0x40		,
0		,0x53		,0x50		,
0		,0x54		,0x60		,
0		,0x55		,0x40		,
0		,0x56		,0xED		,
0		,0x57		,0x96		,
0		,0x58		,0x4A		,
0		,0x59		,0xDE		,
0		,0x5A		,0x88		,
0		,0x5B		,0xC8		,
0		,0x5C		,0x2D		,
0		,0x5D		,0x1		,
0		,0x5E		,0x0		,
0		,0x5F		,0xB8		,
0		,0x60		,0x40		,
0		,0x61		,0x14		,
0		,0x62		,0x13		,
0		,0x63		,0x30		,
0		,0x64		,0x59		,
0		,0x65		,0x7		,
0		,0x66		,0xF0		,
0		,0x67		,0x47		,
0		,0x68		,0xA1		,
0		,0x69		,0x80		,
0		,0x6A		,0x0		,
0		,0x6B		,0x0		,
0		,0x6C		,0xC0		,
0		,0x6D		,0x0		,
0		,0x6E		,0x0		,
0		,0x6F		,0x0		,
0		,0x70		,0x0		,
0		,0x71		,0x0		,
0		,0x72		,0x0		,
0		,0x73		,0x0		,
0		,0x74		,0x2F		,
0		,0x75		,0x0		,
0		,0x76		,0x0		,
0		,0x77		,0x0		,
0		,0x78		,0x0		,
0		,0x79		,0x40		,
0		,0x7A		,0x20		,
0		,0x7B		,0x40		,
0		,0x7C		,0x80		,
0		,0x7D		,0xFF		,
0		,0x7E		,0x20		,
0		,0x7F		,0x40		,
0		,0x80		,0x10		,
0		,0x81		,0x0		,
0		,0x82		,0xE5		,
0		,0x83		,0xC4		,
0		,0x84		,0xE9		,
0		,0x85		,0x52		,
0		,0x86		,0x5F		,
0		,0x87		,0x53		,
0		,0x88		,0x20		,
0		,0x89		,0x43		,
0		,0x8A		,0x11		,
0		,0x8B		,0x8		,
0		,0x8C		,0x43		,
0		,0x8D		,0x11		,
0		,0x8E		,0x8		,
0		,0x8F		,0x0		,
0		,0x90		,0x60		,
0		,0x91		,0x5B		,
0		,0x92		,0x80		,
0		,0x93		,0xE4		,
0		,0x94		,0x34		,
0		,0x95		,0x0		,
0		,0x96		,0x0		,
0		,0x97		,0x7		,
0		,0x98		,0x0		,
0		,0x99		,0xB0		,
0		,0x9A		,0x68		,
0		,0x9B		,0x50		,
0		,0x9C		,0x84		,
0		,0x9D		,0xA9		,
0		,0x9E		,0x11		,
0		,0x9F		,0x4		,
0		,0xA0		,0x44		,
0		,0xA1		,0x14		,
0		,0xA2		,0x9C		,
0		,0xA3		,0x15		,
0		,0xA4		,0xF6		,
0		,0xA5		,0x36		,
0		,0xA6		,0x16		,
0		,0xA7		,0x3F		,
0		,0xA8		,0x1		,
0		,0xA9		,0x8		,
0		,0xAA		,0x0		,
0		,0xAB		,0x0		,
0		,0xAC		,0x0		,
0		,0xAD		,0x65		,
0		,0xAE		,0x87		,
0		,0xAF		,0x56		,
0		,0xB0		,0x52		,
0		,0xB1		,0x55		,
0		,0xB2		,0x35		,
0		,0xB3		,0x13		,
0		,0xB4		,0x88		,
0		,0xB5		,0x23		,
0		,0xB6		,0x28		,
0		,0xB7		,0x3C		,
0		,0xB8		,0x1		,
0		,0xB9		,0x5B		,
0		,0xBA		,0x0		,
0		,0xBB		,0x0		,
0		,0xBC		,0x0		,
0		,0xBD		,0x0		,
0		,0xBE		,0x0		,
0		,0xBF		,0x0		,
0		,0xC0		,0x0		,
0		,0xC1		,0x0		,
0		,0xC2		,0x0		,
0		,0xC3		,0x0		,
0		,0xC4		,0x0		,
0		,0xC5		,0x0		,
0		,0xC6		,0x0		,
0		,0xC7		,0x0		,
0		,0xC8		,0x0		,
0		,0xC9		,0x0		,
0		,0xCA		,0x0		,
0		,0xCB		,0x0		,
0		,0xCC		,0x0		,
0		,0xCD		,0x0		,
0		,0xCE		,0x0		,
0		,0xCF		,0x0		,
0		,0xD0		,0x0		,
0		,0xD1		,0x0		,
0		,0xD2		,0x0		,
0		,0xD3		,0x0		,
0		,0xD4		,0x0		,
0		,0xD5		,0x0		,
0		,0xD6		,0x0		,
0		,0xD7		,0x0		,
0		,0xD8		,0x0		,
0		,0xD9		,0xA0		,
0		,0xDA		,0x0		,
0		,0xDB		,0x0		,
0		,0xDC		,0x0		,
0		,0xDD		,0x0		,
0		,0xDE		,0x0		,
0		,0xDF		,0x9		,
0		,0xE0		,0x8		,
0		,0xE1		,0x8		,
0		,0xE2		,0xA8		,
0		,0xE3		,0x0		,
0		,0xE4		,0x0		,
0		,0xE5		,0x0		,
0		,0xE6		,0x0		,
0		,0xE7		,0xB4		,
0		,0xE8		,0xA		,
0		,0xE9		,0x0		,
0		,0xEA		,0x0		,
0		,0xEB		,0x0		,
0		,0xEC		,0x0		,
0		,0xED		,0x0		,
0		,0xEE		,0x0		,
0		,0xEF		,0xB4		,
0		,0xF0		,0x91		,
0		,0xF1		,0x0		,
0		,0xF2		,0x0		,
0		,0xF3		,0x0		,
0		,0xF4		,0x0		,
0		,0xF5		,0x0		,
0		,0xF6		,0x0		,
0		,0xF7		,0x0		,
0		,0xF8		,0x0		,
0		,0xF9		,0x0		,
0		,0xFA		,0x0		,
0		,0xFB		,0x80		,
0		,0xFC		,0x10		,
0		,0xFD		,0x2		,
0		,0xFE		,0x20		,
0		,0xFF		,0xAA		,
1		,0x9		,0x0		,
1		,0xA		,0x0		,
1		,0xB		,0x0		,
1		,0xC		,0x8		,
1		,0xD		,0x0		,
1		,0x14		,0x8		,
1		,0x5A		,0x3C		,
1		,0x5B		,0x0		,
1		,0x5C		,0x0		,
1		,0x5D		,0x0		,
1		,0x5E		,0x0		,
1		,0x5F		,0x0		,
1		,0x60		,0x0		,
1		,0x61		,0xAC		,
1		,0x62		,0x24		,
1		,0x63		,0x0		,
1		,0x64		,0x0		,
1		,0x65		,0x0		,
1		,0x66		,0x0		,
1		,0x67		,0x0		,
1		,0x68		,0x0		,
1		,0x69		,0x0		,
1		,0x6A		,0x0		,
1		,0x6B		,0x0		,
1		,0x74		,0x0		,
1		,0x79		,0x0		,
1		,0x80		,0x5		,
1		,0x81		,0x0		,
1		,0x82		,0x40		,
1		,0x83		,0x0		,
1		,0x84		,0x40		,
1		,0x85		,0x37		,
1		,0x86		,0x2		,
1		,0x87		,0x20		,
1		,0x88		,0x0		,
1		,0x89		,0x20		,
1		,0x8A		,0x0		,
1		,0x8B		,0x3		,
1		,0x8C		,0x60		,
1		,0x8D		,0x30		,
1		,0x8E		,0x88		,
1		,0x8F		,0x11		,
1		,0x90		,0x0		,
1		,0x91		,0x0		,
1		,0x92		,0x71		,
1		,0x93		,0xE7		,
1		,0x94		,0x23		,
1		,0x95		,0x52		,
1		,0x96		,0x73		,
1		,0x97		,0x96		,
1		,0x98		,0xA5		,
1		,0x99		,0x3		,
1		,0x9A		,0xBA		,
1		,0x9B		,0x95		,
1		,0x9C		,0x25		,
1		,0x9D		,0xD4		,
1		,0x9E		,0x0		,
1		,0x9F		,0x0		,
1		,0xA0		,0xFD		,
1		,0xA1		,0x6D		,
1		,0xA2		,0x63		,
1		,0xA3		,0x52		,
1		,0xFF		,0x55		,
0xff,0xff,0xff};


// Mode : QAM_B_256QAM
DMD_u8_t DMD_REG_QAM_B_256QAM[]={
0		,0x0		,0x53		,
0		,0x1		,0x0		,
0		,0x2		,0xC0		,
0		,0x3		,0x0		,
0		,0x4		,0x0		,
0		,0x5		,0x0		,
0		,0x6		,0x0		,
0		,0x7		,0x0		,
0		,0x8		,0x0		,
0		,0x9		,0x0		,
0		,0xA		,0x16		,
0		,0xB		,0x35		,
0		,0xC		,0x56		,
0		,0xD		,0x8F		,
0		,0xE		,0x44		,
0		,0xF		,0xED		,
0		,0x10		,0x0		,
0		,0x11		,0x14		,
0		,0x12		,0xE4		,
0		,0x13		,0x74		,
0		,0x14		,0x8		,
0		,0x15		,0x5		,
0		,0x16		,0x63		,
0		,0x17		,0x0		,
0		,0x18		,0x0		,
0		,0x19		,0x0		,
0		,0x1A		,0x0		,
0		,0x1B		,0x0		,
0		,0x1C		,0x0		,
0		,0x1D		,0x0		,
0		,0x1E		,0x0		,
0		,0x1F		,0x0		,
0		,0x20		,0x0		,
0		,0x21		,0x50		,
0		,0x22		,0x60		,
0		,0x23		,0x36		,
0		,0x24		,0x2		,
0		,0x25		,0x0		,
0		,0x26		,0x0		,
0		,0x27		,0x0		,
0		,0x28		,0x0		,
0		,0x29		,0x0		,
0		,0x2A		,0x20		,
0		,0x2B		,0xC0		,
0		,0x2C		,0x23		,
0		,0x2D		,0x3F		,
0		,0x2E		,0x3F		,
0		,0x2F		,0x0		,
0		,0x30		,0x2E		,
0		,0x31		,0x0		,
0		,0x32		,0x0		,
0		,0x33		,0x81		,
0		,0x34		,0x0		,
0		,0x35		,0x26		,
0		,0x36		,0x21		,
0		,0x37		,0x88		,
0		,0x38		,0x3		,
0		,0x39		,0x19		,
0		,0x3A		,0x85		,
0		,0x3B		,0x5		,
0		,0x3C		,0xC9		,
0		,0x3D		,0x2		,
0		,0x3E		,0x30		,
0		,0x3F		,0x69		,
0		,0x40		,0x1F		,
0		,0x41		,0xF0		,
0		,0x42		,0x0		,
0		,0x43		,0x96		,
0		,0x44		,0x72		,
0		,0x45		,0x1B		,
0		,0x46		,0x2D		,
0		,0x47		,0x1A		,
0		,0x48		,0x31		,
0		,0x49		,0xFE		,
0		,0x4A		,0x96		,
0		,0x4B		,0x7		,
0		,0x4C		,0x26		,
0		,0x4D		,0xE3		,
0		,0x4E		,0x22		,
0		,0x4F		,0x1B		,
0		,0x50		,0x26		,
0		,0x51		,0x12		,
0		,0x52		,0x40		,
0		,0x53		,0x50		,
0		,0x54		,0x60		,
0		,0x55		,0x40		,
0		,0x56		,0xED		,
0		,0x57		,0x96		,
0		,0x58		,0x4A		,
0		,0x59		,0xDE		,
0		,0x5A		,0x88		,
0		,0x5B		,0xC8		,
0		,0x5C		,0x2D		,
0		,0x5D		,0x1		,
0		,0x5E		,0x0		,
0		,0x5F		,0xB8		,
0		,0x60		,0x40		,
0		,0x61		,0x14		,
0		,0x62		,0x13		,
0		,0x63		,0x30		,
0		,0x64		,0x59		,
0		,0x65		,0x7		,
0		,0x66		,0xF0		,
0		,0x67		,0x47		,
0		,0x68		,0xA1		,
0		,0x69		,0x80		,
0		,0x6A		,0x0		,
0		,0x6B		,0x0		,
0		,0x6C		,0xC0		,
0		,0x6D		,0x0		,
0		,0x6E		,0x0		,
0		,0x6F		,0x0		,
0		,0x70		,0x0		,
0		,0x71		,0x0		,
0		,0x72		,0x0		,
0		,0x73		,0x0		,
0		,0x74		,0x2F		,
0		,0x75		,0x0		,
0		,0x76		,0x0		,
0		,0x77		,0x0		,
0		,0x78		,0x0		,
0		,0x79		,0x40		,
0		,0x7A		,0x20		,
0		,0x7B		,0x40		,
0		,0x7C		,0x80		,
0		,0x7D		,0xFF		,
0		,0x7E		,0x20		,
0		,0x7F		,0x40		,
0		,0x80		,0x10		,
0		,0x81		,0x0		,
0		,0x82		,0xE5		,
0		,0x83		,0xC4		,
0		,0x84		,0xE9		,
0		,0x85		,0x52		,
0		,0x86		,0x5F		,
0		,0x87		,0x53		,
0		,0x88		,0x20		,
0		,0x89		,0x43		,
0		,0x8A		,0x11		,
0		,0x8B		,0x8		,
0		,0x8C		,0x43		,
0		,0x8D		,0x11		,
0		,0x8E		,0x8		,
0		,0x8F		,0x0		,
0		,0x90		,0x60		,
0		,0x91		,0x5B		,
0		,0x92		,0x80		,
0		,0x93		,0xE4		,
0		,0x94		,0x34		,
0		,0x95		,0x0		,
0		,0x96		,0x0		,
0		,0x97		,0x7		,
0		,0x98		,0x0		,
0		,0x99		,0xB0		,
0		,0x9A		,0x68		,
0		,0x9B		,0x50		,
0		,0x9C		,0x84		,
0		,0x9D		,0xA9		,
0		,0x9E		,0x11		,
0		,0x9F		,0x4		,
0		,0xA0		,0x44		,
0		,0xA1		,0x14		,
0		,0xA2		,0x9C		,
0		,0xA3		,0x15		,
0		,0xA4		,0xF6		,
0		,0xA5		,0x36		,
0		,0xA6		,0x16		,
0		,0xA7		,0x3F		,
0		,0xA8		,0x1		,
0		,0xA9		,0x8		,
0		,0xAA		,0x0		,
0		,0xAB		,0x0		,
0		,0xAC		,0x0		,
0		,0xAD		,0x65		,
0		,0xAE		,0x87		,
0		,0xAF		,0x56		,
0		,0xB0		,0x52		,
0		,0xB1		,0x55		,
0		,0xB2		,0x35		,
0		,0xB3		,0x13		,
0		,0xB4		,0x88		,
0		,0xB5		,0x23		,
0		,0xB6		,0x28		,
0		,0xB7		,0x3C		,
0		,0xB8		,0x1		,
0		,0xB9		,0x5B		,
0		,0xBA		,0x0		,
0		,0xBB		,0x0		,
0		,0xBC		,0x0		,
0		,0xBD		,0x0		,
0		,0xBE		,0x0		,
0		,0xBF		,0x0		,
0		,0xC0		,0x0		,
0		,0xC1		,0x0		,
0		,0xC2		,0x0		,
0		,0xC3		,0x0		,
0		,0xC4		,0x0		,
0		,0xC5		,0x0		,
0		,0xC6		,0x0		,
0		,0xC7		,0x0		,
0		,0xC8		,0x0		,
0		,0xC9		,0x0		,
0		,0xCA		,0x0		,
0		,0xCB		,0x0		,
0		,0xCC		,0x0		,
0		,0xCD		,0x0		,
0		,0xCE		,0x0		,
0		,0xCF		,0x0		,
0		,0xD0		,0x0		,
0		,0xD1		,0x0		,
0		,0xD2		,0x0		,
0		,0xD3		,0x0		,
0		,0xD4		,0x0		,
0		,0xD5		,0x0		,
0		,0xD6		,0x0		,
0		,0xD7		,0x0		,
0		,0xD8		,0x0		,
0		,0xD9		,0xA0		,
0		,0xDA		,0x0		,
0		,0xDB		,0x0		,
0		,0xDC		,0x0		,
0		,0xDD		,0x0		,
0		,0xDE		,0x0		,
0		,0xDF		,0x9		,
0		,0xE0		,0x8		,
0		,0xE1		,0x8		,
0		,0xE2		,0xA8		,
0		,0xE3		,0x0		,
0		,0xE4		,0x0		,
0		,0xE5		,0x0		,
0		,0xE6		,0x0		,
0		,0xE7		,0xB4		,
0		,0xE8		,0xA		,
0		,0xE9		,0x0		,
0		,0xEA		,0x0		,
0		,0xEB		,0x0		,
0		,0xEC		,0x0		,
0		,0xED		,0x0		,
0		,0xEE		,0x0		,
0		,0xEF		,0xB4		,
0		,0xF0		,0x91		,
0		,0xF1		,0x0		,
0		,0xF2		,0x0		,
0		,0xF3		,0x0		,
0		,0xF4		,0x0		,
0		,0xF5		,0x0		,
0		,0xF6		,0x0		,
0		,0xF7		,0x0		,
0		,0xF8		,0x0		,
0		,0xF9		,0x0		,
0		,0xFA		,0x0		,
0		,0xFB		,0x80		,
0		,0xFC		,0x10		,
0		,0xFD		,0x2		,
0		,0xFE		,0x20		,
0		,0xFF		,0xAA		,
1		,0x9		,0x0		,
1		,0xA		,0x0		,
1		,0xB		,0x0		,
1		,0xC		,0x8		,
1		,0xD		,0x0		,
1		,0x14		,0x8		,
1		,0x5A		,0x3C		,
1		,0x5B		,0x0		,
1		,0x5C		,0x0		,
1		,0x5D		,0x0		,
1		,0x5E		,0x0		,
1		,0x5F		,0x0		,
1		,0x60		,0x0		,
1		,0x61		,0xAC		,
1		,0x62		,0x24		,
1		,0x63		,0x0		,
1		,0x64		,0x0		,
1		,0x65		,0x0		,
1		,0x66		,0x0		,
1		,0x67		,0x0		,
1		,0x68		,0x0		,
1		,0x69		,0x0		,
1		,0x6A		,0x0		,
1		,0x6B		,0x0		,
1		,0x74		,0x0		,
1		,0x79		,0x0		,
1		,0x80		,0x5		,
1		,0x81		,0x0		,
1		,0x82		,0x40		,
1		,0x83		,0x0		,
1		,0x84		,0x40		,
1		,0x85		,0x37		,
1		,0x86		,0x2		,
1		,0x87		,0x20		,
1		,0x88		,0x0		,
1		,0x89		,0x20		,
1		,0x8A		,0x0		,
1		,0x8B		,0x3		,
1		,0x8C		,0x60		,
1		,0x8D		,0x30		,
1		,0x8E		,0x88		,
1		,0x8F		,0x11		,
1		,0x90		,0x0		,
1		,0x91		,0x0		,
1		,0x92		,0x76		,
1		,0x93		,0xA6		,
1		,0x94		,0x19		,
1		,0x95		,0x4F		,
1		,0x96		,0x27		,
1		,0x97		,0x49		,
1		,0x98		,0xA5		,
1		,0x99		,0x3		,
1		,0x9A		,0xBA		,
1		,0x9B		,0x95		,
1		,0x9C		,0x25		,
1		,0x9D		,0xD4		,
1		,0x9E		,0x0		,
1		,0x9F		,0x0		,
1		,0xA0		,0xFD		,
1		,0xA1		,0x6D		,
1		,0xA2		,0x63		,
1		,0xA3		,0x52		,
1		,0xFF		,0x55		,
0xff,0xff,0xff};

DMD_u8_t DMD_I2C_SLAVE[DMD_MAX_DEVICE][DMD_REG_BANK] ={ {0x18,0x10} , {0x19,0x11} , {0x1A,0x12} , {0x1B,0x13} };


DMD_u32_t MN88436_REG_AUTOCTRL_SIZE = 673;

DMD_u8_t  MN88436_REG_AUTOCTRL[] = {
	0x10	,0x00	,0xc0	,0x02	,0xa1	,0x10	,0x25	,0x20
	,0x4b	,0x10	,0x1b	,0x20	,0x51	,0x10	,0x64	,0x20
	,0xf7	,0x10	,0x0a	,0x20	,0xeb	,0x30	,0xc4	,0x70
	,0x60	,0x90	,0x00	,0x78	,0x82	,0x00	,0x1f	,0x10
	,0x0c	,0x20	,0xeb	,0x30	,0xec	,0x70	,0xbf	,0x20
	,0xec	,0x30	,0x5b	,0x70	,0x40	,0x14	,0x30	,0xec
	,0x75	,0x20	,0xec	,0x30	,0xc4	,0x70	,0x02	,0x90
	,0x00	,0x05	,0x0d	,0x82	,0x00	,0x73	,0x82	,0x00
	,0x41	,0x30	,0xc4	,0x70	,0x01	,0xb0	,0x00	,0x1f
	,0xc4	,0x02	,0xa5	,0x68	,0x88	,0x90	,0x00	,0x63
	,0x80	,0x00	,0x53	,0x10	,0x88	,0xc0	,0x02	,0xa5
	,0x20	,0x5b	,0x30	,0xec	,0x70	,0xbf	,0x20	,0xec
	,0x80	,0x00	,0x1f	,0x10	,0xc8	,0xc0	,0x02	,0xa5
	,0x20	,0x5b	,0x30	,0xec	,0x74	,0x40	,0x20	,0xec
	,0x80	,0x00	,0x1f	,0x08	,0xb0	,0x00	,0x73	,0x01
	,0x10	,0x58	,0x20	,0xb9	,0x30	,0xed	,0x70	,0xfc
	,0x20	,0xed	,0x82	,0x01	,0x54	,0x10	,0x07	,0x20
	,0x4b	,0x10	,0x12	,0x20	,0x51	,0x10	,0x5b	,0x20
	,0xb9	,0x10	,0x01	,0x20	,0xeb	,0x10	,0x00	,0xc0
	,0x02	,0xa0	,0x20	,0x5e	,0x10	,0x94	,0x20	,0x5d
	,0x10	,0x00	,0xc0	,0x02	,0xa4	,0x82	,0x02	,0x3c
	,0x0c	,0x82	,0x02	,0x2c	,0x09	,0x82	,0x01	,0x77
	,0xc4	,0x02	,0xa4	,0x40	,0xc0	,0x02	,0xa4	,0x14
	,0x10	,0x3c	,0x69	,0xb0	,0x00	,0xa5	,0x82	,0x01
	,0x2a	,0x10	,0x02	,0x20	,0xeb	,0xc4	,0x02	,0xa0
	,0x68	,0x0f	,0xc0	,0x02	,0xa0	,0x20	,0x5e	,0x10
	,0x94	,0x20	,0x5d	,0x10	,0x00	,0xc0	,0x02	,0xa4
	,0x82	,0x02	,0x3c	,0x0c	,0x82	,0x02	,0x2c	,0x09
	,0x82	,0x01	,0x77	,0xc4	,0x02	,0xa4	,0x40	,0xc0
	,0x02	,0xa4	,0x14	,0x10	,0x3c	,0x69	,0xb0	,0x00
	,0xd8	,0x82	,0x01	,0x2a	,0x10	,0x04	,0x20	,0xeb
	,0xc4	,0x02	,0xa0	,0x60	,0x1e	,0xc0	,0x02	,0xa0
	,0x20	,0x5e	,0x10	,0x94	,0x20	,0x5d	,0x10	,0x00
	,0xc0	,0x02	,0xa4	,0x82	,0x02	,0x3c	,0x0c	,0x82
	,0x02	,0x2c	,0x09	,0x82	,0x01	,0x77	,0xc4	,0x02
	,0xa4	,0x40	,0xc0	,0x02	,0xa4	,0x14	,0x10	,0x3c
	,0x69	,0xb0	,0x01	,0x0b	,0x82	,0x01	,0x2a	,0x80
	,0x00	,0x91	,0x30	,0xea	,0xc0	,0x02	,0xa2	,0x10
	,0x04	,0x20	,0xba	,0x10	,0x47	,0x20	,0x60	,0x10
	,0x05	,0x20	,0xba	,0x30	,0xbd	,0x70	,0x20	,0xc0
	,0x02	,0xa3	,0x30	,0xea	,0xc5	,0x02	,0xa2	,0x69
	,0xb0	,0x01	,0x2a	,0xc4	,0x02	,0xa3	,0x60	,0x00
	,0xb0	,0x01	,0xed	,0x01	,0x10	,0x05	,0x20	,0xeb
	,0x10	,0x10	,0x20	,0xac	,0x10	,0xf4	,0x20	,0xe7
	,0x10	,0x04	,0x20	,0xaa	,0x10	,0x0	,0xc0	,0x02
	,0xa0	,0x20	,0x5e	,0x10	,0x94	,0x20	,0x5d	,0x30
	,0xc4	,0x70	,0x01	,0x90	,0x00	,0x05	,0x01	,0x82
	,0x01	,0x7f	,0x08	,0xb0	,0x01	,0x77	,0x01	,0x30
	,0xea	,0xc0	,0x02	,0xa2	,0x10	,0x5b	,0x20	,0xb9
	,0x10	,0x04	,0x20	,0xba	,0x10	,0x47	,0x20	,0x60
	,0x10	,0x05	,0x20	,0xba	,0x30	,0xbd	,0x70	,0x20
	,0xc0	,0x02	,0xa3	,0x30	,0xea	,0xc5	,0x02	,0xa2
	,0x69	,0xb0	,0x01	,0x7f	,0xc4	,0x02	,0xa3	,0x60
	,0x00	,0x90	,0x01	,0xaf	,0xb0	,0x01	,0xce	,0x10
	,0x10	,0x20	,0xac	,0x10	,0xf4	,0x20	,0xe7	,0x10
	,0x04	,0x20	,0xaa	,0x30	,0xc6	,0xc0	,0x02	,0xa1
	,0x70	,0x04	,0x90	,0x00	,0x05	,0x30	,0xed	,0x70
	,0xfb	,0x74	,0x00	,0x20	,0xed	,0x01	,0x10	,0x10
	,0x20	,0xac	,0x10	,0x90	,0x20	,0xe7	,0x10	,0x04
	,0x20	,0xaa	,0x30	,0xc6	,0xc0	,0x02	,0xa1	,0x70
	,0x04	,0x90	,0x00	,0x05	,0x30	,0xed	,0x70	,0xfb
	,0x74	,0x04	,0x20	,0xed	,0x01	,0x30	,0x5e	,0x70
	,0xff	,0x92	,0x02	,0x11	,0x30	,0x5e	,0x70	,0x80
	,0xb2	,0x02	,0x1a	,0x30	,0x5e	,0x68	,0x0f	,0x92
	,0x02	,0x23	,0x30	,0xeb	,0x74	,0xf0	,0x20	,0xeb
	,0x82	,0x01	,0x7f	,0x82	,0x02	,0x3c	,0x80	,0x02
	,0x02	,0x30	,0xed	,0x70	,0xfc	,0x74	,0x01	,0x20
	,0xed	,0x01	,0x30	,0xed	,0x70	,0xfc	,0x74	,0x02
	,0x20	,0xed	,0x01	,0x30	,0xed	,0x70	,0xfc	,0x74
	,0x03	,0x20	,0xed	,0x01	,0x30	,0xc6	,0xc0	,0x02
	,0xa1	,0x70	,0x04	,0x90	,0x00	,0x05	,0x08	,0xb0
	,0x02	,0x2c	,0x09	,0x01	,0x30	,0xeb	,0x74	,0x10
	,0x20	,0xeb	,0x30	,0xd8	,0x14	,0x70	,0x07	,0x90
	,0x02	,0x51	,0x11	,0x68	,0x05	,0x90	,0x02	,0x51
	,0x01	,0x30	,0xcf	,0xc0	,0x02	,0xa6	,0xc4	,0x02
	,0xa6	,0x70	,0xf8	,0x90	,0x02	,0x61	,0xb0	,0x02
	,0x7e	,0xc4	,0x02	,0xa6	,0x4c	,0x4c	,0x4c	,0x4c
	,0x4c	,0xc0	,0x02	,0xa6	,0x30	,0xd0	,0x48	,0x48
	,0x48	,0x14	,0xc4	,0x02	,0xa6	,0x61	,0xc0	,0x02
	,0xa6	,0x20	,0xee	,0x80	,0x02	,0x88	,0x10	,0xff
	,0xc0	,0x02	,0xa6	,0x20	,0xee	,0x80	,0x02	,0x88
	,0xc4	,0x02	,0xa6	,0x14	,0x30	,0xef	,0x69	,0x88
	,0x02	,0x93	,0x01	,0x30	,0xa3	,0x70	,0x07	,0x74
	,0x28	,0x20	,0xa3	,0x70	,0x07	,0x20	,0xa3	,0x01
	,0x72};

/* MxLWare Driver version for MxL603 */
UINT8 MxLWare603DrvVersion[] = {2, 1, 1, 3, 0}; 


MXL603_REG_CTRL_INFO_T MxL603_OverwriteDefaults[] = 
{
  {0x14, 0xFF, 0x13},
  {0x6D, 0xFF, 0x8A},
  {0x6D, 0xFF, 0x0A},
  {0xDF, 0xFF, 0x19},
  {0x45, 0xFF, 0x1B},
  {0xA9, 0xFF, 0x59},
  {0xAA, 0xFF, 0x6A},
  {0xBE, 0xFF, 0x4C},
  {0xCF, 0xFF, 0x25},
  {0xD0, 0xFF, 0x34},
  {0x77, 0xFF, 0xE7},
  {0x78, 0xFF, 0xE3},
  {0x6F, 0xFF, 0x51},
  {0x7B, 0xFF, 0x84},
  {0x7C, 0xFF, 0x9F},
  {0x56, 0xFF, 0x41},
  {0xCD, 0xFF, 0x64},
  {0xC3, 0xFF, 0x2C},
  {0x9D, 0xFF, 0x61},
  {0xF7, 0xFF, 0x52},
  {0x58, 0xFF, 0x81},
  {0x00, 0xFF, 0x01},
  {0x62, 0xFF, 0x02},
  {0x00, 0xFF, 0x00},
  {0,    0,    0}
};

MXL603_REG_CTRL_INFO_T MxL603_DigitalIsdbtAtsc[] = 
{
  {0x0C, 0xFF, 0x00},
  {0x13, 0xFF, 0x04},
  {0x53, 0xFF, 0xFE},
  {0x57, 0xFF, 0x91},
  {0x62, 0xFF, 0xC2},
  {0x6E, 0xFF, 0x01},
  {0x6F, 0xFF, 0x51},
  {0x87, 0xFF, 0x77},
  {0x88, 0xFF, 0x55},
  {0x93, 0xFF, 0x22},
  {0x97, 0xFF, 0x02},
  {0xBA, 0xFF, 0x30},
  {0x98, 0xFF, 0xAF},
  {0x9B, 0xFF, 0x20},
  {0x9C, 0xFF, 0x1E},
  {0xA0, 0xFF, 0x18},
  {0xA5, 0xFF, 0x09},
  {0xC2, 0xFF, 0xA9},
  {0xC5, 0xFF, 0x7C},
  {0xCD, 0xFF, 0xEB},
  {0xCE, 0xFF, 0x7F},
  {0xD5, 0xFF, 0x03},
  {0xD9, 0xFF, 0x04},
  {0,    0,    0}
};
// Digital DVB-C application mode setting
MXL603_REG_CTRL_INFO_T MxL603_DigitalDvbc[] = 
{
  {0x0C, 0xFF, 0x00},
  {0x13, 0xFF, 0x04},
  {0x53, 0xFF, 0x7E},
  {0x57, 0xFF, 0x91},
  {0x5C, 0xFF, 0xB1},
  {0x62, 0xFF, 0xF2},
  {0x6E, 0xFF, 0x03},
  {0x6F, 0xFF, 0xD1},
  {0x87, 0xFF, 0x77},
  {0x88, 0xFF, 0x55},
  {0x93, 0xFF, 0x33},
  {0x97, 0xFF, 0x03},
  {0xBA, 0xFF, 0x40},
  {0x98, 0xFF, 0xAF},
  {0x9B, 0xFF, 0x20},
  {0x9C, 0xFF, 0x1E},
  {0xA0, 0xFF, 0x18},
  {0xA5, 0xFF, 0x09},
  {0xC2, 0xFF, 0xA9},
  {0xC5, 0xFF, 0x7C},
  {0xCD, 0xFF, 0x64},
  {0xCE, 0xFF, 0x7C},
  {0xD5, 0xFF, 0x05},
  {0xD9, 0xFF, 0x00},
  {0xEA, 0xFF, 0x00},
  {0xDC, 0xFF, 0x1C},
  {0,    0,    0}
};
// Digital DVB-T 6MHz application mode setting
 MXL603_REG_CTRL_INFO_T MxL603_DigitalDvbt[] = 
{
  {0x0C, 0xFF, 0x00},
  {0x13, 0xFF, 0x04},
  {0x53, 0xFF, 0xFE},
  {0x57, 0xFF, 0x91},
  {0x62, 0xFF, 0xC2},
  {0x6E, 0xFF, 0x01},
  {0x6F, 0xFF, 0x51},
  {0x87, 0xFF, 0x77},
  {0x88, 0xFF, 0x55},
  {0x93, 0xFF, 0x22},
  {0x97, 0xFF, 0x02},
  {0xBA, 0xFF, 0x30},
  {0x98, 0xFF, 0xAF},
  {0x9B, 0xFF, 0x20},
  {0x9C, 0xFF, 0x1E},
  {0xA0, 0xFF, 0x18},
  {0xA5, 0xFF, 0x09},
  {0xC2, 0xFF, 0xA9},
  {0xC5, 0xFF, 0x7C},
  {0xCD, 0xFF, 0x64},
  {0xCE, 0xFF, 0x7C},
  {0xD5, 0xFF, 0x03},
  {0xD9, 0xFF, 0x04},
  {0,    0,    0}
};
/* **************************************************** */
/* Log Table */
/* **************************************************** */
DMD_s32_t	logtbl[] = {
0	,-1000,-699	,-523,-398,
-301,-222 ,-155	,-97 ,-46 ,
0	,41	,79	,114	,146	,
176	,204	,230	,255	,
279	,301	,322	,342	,
362	,380	,398	,415	,
431	,447	,462	,477	,
491	,505	,519	,531	,
544	,556	,568	,580	,
591	,602	,613	,623	,
633	,643	,653	,663	,
672	,681	,690	,699	,
708	,716	,724	,732	,
740	,748	,756	,763	,
771	,778	,785	,792	,
799	,806	,813	,820	,
826	,833	,839	,845	,
851	,857	,863	,869	,
875	,881	,886	,892	,
898	,903	,908	,914	,
919	,924	,929	,934	,
940	,944	,949	,954	,
959	,964	,968	,973	,
978	,982	,987	,991	,
996	,1000};

/* Calculate Log10 */
DMD_u32_t log10_easy( DMD_u32_t cnr )
{
	DMD_u32_t	c;
	DMD_s32_t	ret;
	c = 0;

	while( cnr > 100 ){
		cnr = cnr / 10;
		c++;
	}
	ret = logtbl[cnr] + c*1000 + 1000;

	return ret;
}
struct mndmd_state
{
	struct i2c_adapter* i2c;

	/* Configuration settings */
	const struct mndmd_config* config;

	struct dvb_frontend frontend;

};

DMD_PARAMETER_t param;

/*! Write 1byte */
DMD_ERROR_t DMD_I2C_Write(struct dvb_frontend* fe,DMD_u8_t	slvadr , DMD_u8_t adr , DMD_u8_t data )
{
	//TODO:	Please call I2C 1byte Write API
	struct mndmd_state *state = fe->demodulator_priv;
	int ret;
	u8 buf[] = { adr, data };
	struct i2c_msg msg = {
		.addr = slvadr,
		.flags = 0,
		.buf = buf,
		.len = 2
	};

	ret = i2c_transfer(state->i2c, &msg, 1);

	if (ret != 1)
		printk(" writereg error (adr == 0x%02x, val == 0x%02x, "
			"ret == %i)\n", adr, data, ret);

	return (ret != 1) ? -EREMOTEIO : 0;



}

/*! Read 1byte */
DMD_ERROR_t DMD_I2C_Read(struct dvb_frontend* fe,DMD_u8_t	slvadr , DMD_u8_t adr , DMD_u8_t *data )
{
	//TODO:	Please call I2C 1byte Write API
	struct mndmd_state *state = fe->demodulator_priv;

		int ret;
		u8 b0[] = { adr };
		struct i2c_msg msg[] = {
			{
				.addr = slvadr,
				.flags = 0,
				.buf = b0,
				.len = 1
			}, {
				.addr = slvadr,
				.flags = I2C_M_RD,
				.buf = data,
				.len = 1
			}
		};
		
		ret = i2c_transfer(state->i2c, msg, 2);
		if (ret != 2)
			printk(" readreg error (reg == 0x%02x, ret == %i)\n",
					 adr, ret);

	
		return DMD_E_OK;
}


DMD_ERROR_t	DMD_I2C_MaskWrite(struct dvb_frontend* fe,DMD_u8_t	slvadr , DMD_u8_t adr , DMD_u8_t mask , DMD_u8_t  data )
{
	DMD_u8_t	rd;
	DMD_ERROR_t ret;
	ret =DMD_I2C_Read( fe,slvadr , adr , &rd );
	rd |= mask & data;
	rd &= (mask^0xff) | data;
	ret = DMD_I2C_Write( fe,slvadr , adr ,rd );

	return ret;
}

DMD_ERROR_t DMD_send_registers(struct dvb_frontend* fe, DMD_u8_t* slaveset , DMD_u8_t* regset )
{
	DMD_u32_t	i;
	for(i=0;;)
	{
		if( regset[i] == 0xff ) break;
		DMD_I2C_Write(fe ,slaveset[regset[i]] , regset[i+1] , regset[i+2] );
		i=i+3;
	}
	return DMD_E_OK;
}
int MXL603_Write( struct mndmd_state *state , UINT8 RegAddr, UINT8 RegData)
{
	int ret;

	u8 buf1[]={RegAddr,RegData} ;
	

	struct i2c_msg msg= {
		.addr= state->config->tuner_address,
		.flags=0,
		.buf=buf1,
		.len=2
		};


	ret = i2c_transfer(state->i2c, &msg, 1);

	if (ret != 1)
		printk(" writereg error (reg == 0x%02x, val == 0x%02x, "
			"ret == %i)\n",RegAddr, RegData, ret);

	return (ret != 1) ? 1 : 0;


//	return 0;

	
}

int MXL603_Read(struct mndmd_state *state , UINT8 RegAddr , UINT8 *rdata )
{
	int ret;
	u8 b0[2] = { 0xFB ,RegAddr};

	struct i2c_msg msg[] = {
		{
			.addr = state->config->tuner_address,
			.flags = 0,
			.buf = b0,
			.len = 2
		}, {
			.addr = state->config->tuner_address,
			.flags = I2C_M_RD,
			.buf = rdata,
			.len = 1
		}
	};

	ret = i2c_transfer(state->i2c, msg, 2);

	if (ret != 2)
		printk(" readreg error (reg == 0x%02x, ret == %i)\n",
				 RegAddr, ret);


	return (ret != 2) ? 1 : 0;
//	return 0;
	
}

MXL_STATUS MxLWare603_OEM_WriteRegister(struct dvb_frontend *fe, UINT8 RegAddr, UINT8 RegData)
{
	int Status = 0;

	struct mndmd_state *state= fe->demodulator_priv;
	/* If OEM data is not required, customer should treat devId as I2C slave Address */



	Status = MXL603_Write( state , RegAddr, RegData);


	if ( Status != 0 )
	{

		printk("MxLWare603_OEM_WriteRegister error!!");

	}

	return (MXL_STATUS)Status;
}


MXL_STATUS MxLWare603_OEM_ReadRegister(struct dvb_frontend *fe, UINT8 RegAddr, UINT8 *DataPtr)
{
	int Status = 0;
	struct mndmd_state *state= fe->demodulator_priv;


	Status = MXL603_Read(state , RegAddr, DataPtr);


	if ( Status != 0 )
	{
		printk("MxLWare603_OEM_ReadRegister error!!");
	}


	return ( MXL_STATUS)Status;
}

MXL_STATUS MxL603_Ctrl_ProgramRegisters(struct dvb_frontend *fe,  PMXL603_REG_CTRL_INFO_T ctrlRegInfoPtr)
{
	MXL_STATUS status = MXL_TRUE;
	UINT16 i = 0;
	UINT8 tmp = 0;

	while (status == MXL_TRUE)
	{
		if ((ctrlRegInfoPtr[i].regAddr == 0) && (ctrlRegInfoPtr[i].mask == 0) && (ctrlRegInfoPtr[i].data == 0)) break;

		// Check if partial bits of register were updated
		if (ctrlRegInfoPtr[i].mask != 0xFF)  
		{
			status = MxLWare603_OEM_ReadRegister(fe,ctrlRegInfoPtr[i].regAddr, &tmp);
			if (status != MXL_TRUE) break;;
		}

		tmp &= (UINT8) ~ctrlRegInfoPtr[i].mask;
		tmp |= (UINT8) ctrlRegInfoPtr[i].data;

		status = MxLWare603_OEM_WriteRegister(fe,ctrlRegInfoPtr[i].regAddr, tmp);
		if (status != MXL_TRUE) break;

		i++;
	}

	return status;
}
/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgDevSoftReset
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This API is used to reset MxL603 tuner device. After reset,
--|                 all the device regiaters and modules will be set to power-on  
--|                 default state. 
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_FAILED 
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgDevSoftReset(struct dvb_frontend *fe)
{
	UINT8 status = MXL_SUCCESS;

	//  MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	// Write 0xFF with 0 to reset tuner 
	status = MxLWare603_OEM_WriteRegister(fe, AIC_RESET_REG, 0x00); 

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgDevOverwriteDefaults
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : Register(s) that requires default values to be overwritten 
--|                 during initialization
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgDevOverwriteDefaults(struct dvb_frontend *fe, 
															 MXL_BOOL singleSupply_3_3V)
{
	UINT8 status = MXL_SUCCESS;
	UINT8 readData = 0;

	//  MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	status |= MxL603_Ctrl_ProgramRegisters(fe, MxL603_OverwriteDefaults);

	status |= MxLWare603_OEM_WriteRegister(fe, 0x00, 0x01);
	status |= MxLWare603_OEM_ReadRegister(fe, 0x31, &readData);
	readData &= 0x2F;
	readData |= 0xD0;
	status |= MxLWare603_OEM_WriteRegister(fe, 0x31, readData);
	status |= MxLWare603_OEM_WriteRegister(fe, 0x00, 0x00);


	/* If Single supply 3.3v is used */
	if (MXL_ENABLE == singleSupply_3_3V)
		status |= MxLWare603_OEM_WriteRegister(fe, MAIN_REG_AMP, 0x04);

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgDevXtal
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This API is used to configure XTAL settings of MxL603 tuner
--|                 device. XTAL settings include frequency, capacitance & 
--|                 clock out
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgDevXtal(struct dvb_frontend *fe,  MXL603_XTAL_SET_CFG_T xtalCfg)
{
	UINT8 status = MXL_SUCCESS;
	UINT8 control = 0;

	// MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	// XTAL freq and cap setting, Freq set is located at bit<5>, cap bit<4:0> 
	// and  XTAL clock out enable <0>
	if ((xtalCfg.xtalFreqSel == MXL603_XTAL_16MHz) || (xtalCfg.xtalFreqSel == MXL603_XTAL_24MHz))
	{
		control = (UINT8)((xtalCfg.xtalFreqSel << 5) | (xtalCfg.xtalCap & 0x1F));  
		control |= (xtalCfg.clkOutEnable << 7);
		status = MxLWare603_OEM_WriteRegister(fe, XTAL_CAP_CTRL_REG, control);

		// XTAL frequency div 4 setting <1> 
		control = (0x01 & (UINT8)xtalCfg.clkOutDiv);

		// XTAL sharing mode
		if (xtalCfg.XtalSharingMode == MXL_ENABLE) control |= 0x40;
		else control &= 0x01;

		// program Clock out div & Xtal sharing
		status |= MxLWare603_OEM_WriteRegister(fe, XTAL_ENABLE_DIV_REG, control); 

		// Main regulator re-program
		if (MXL_ENABLE == xtalCfg.singleSupply_3_3V)
			status |= MxLWare603_OEM_WriteRegister(fe, MAIN_REG_AMP, 0x14);
	}
	else 
		status |= MXL_INVALID_PARAMETER;

	return ( MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgDevPowerMode
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This function configures MxL603 power mode 
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgDevPowerMode(struct dvb_frontend *fe, MXL603_PWR_MODE_E powerMode)
{
	UINT8 status = MXL_SUCCESS;

	// MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	switch(powerMode)
	{
	case MXL603_PWR_MODE_SLEEP:
		break;

	case MXL603_PWR_MODE_ACTIVE:
		status |= MxLWare603_OEM_WriteRegister(fe, TUNER_ENABLE_REG, MXL_ENABLE);
		status |= MxLWare603_OEM_WriteRegister(fe, START_TUNE_REG, MXL_ENABLE);
		break;

	case MXL603_PWR_MODE_STANDBY:
		status |= MxLWare603_OEM_WriteRegister(fe, START_TUNE_REG, MXL_DISABLE);
		status |= MxLWare603_OEM_WriteRegister(fe, TUNER_ENABLE_REG, MXL_DISABLE);
		break;

	default:
		status |= MXL_INVALID_PARAMETER;
	}

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgDevGPO
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This API configures GPO pin of MxL603 tuner device.
--|                 There is only 1 GPO pin available in MxL603 device.  
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgDevGPO(struct dvb_frontend *fe, MXL603_GPO_STATE_E gpoState)
{
	UINT8 status = MXL_SUCCESS;
	UINT8 regData = 0;

	//  MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	switch(gpoState)
	{
	case MXL603_GPO_AUTO_CTRL:
	case MXL603_GPO_HIGH:
	case MXL603_GPO_LOW:
		status = MxLWare603_OEM_ReadRegister(fe, GPO_SETTING_REG, &regData);
		if (MXL603_GPO_AUTO_CTRL == gpoState)
			regData &= 0xFE;
		else
		{
			regData &= 0xFC;
			regData |= (UINT8)(0x01 | (gpoState << 1)); 
		}

		status |= MxLWare603_OEM_WriteRegister(fe, GPO_SETTING_REG, regData);
		break;

	default:
		status = MXL_INVALID_PARAMETER;
	}

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_ReqDevVersionInfo
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This function is used to get MxL603 version information.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_ReqDevVersionInfo(struct dvb_frontend *fe, MXL603_VER_INFO_T* mxlDevVerInfoPtr)
														
{
	UINT8 status = MXL_SUCCESS;
	UINT8 readBack = 0;
	UINT8 k = 0;


	// MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	if (mxlDevVerInfoPtr)
	{
		status |= MxLWare603_OEM_ReadRegister(fe, CHIP_ID_REQ_REG, &readBack);
		mxlDevVerInfoPtr->chipId = (readBack & 0xFF); 

		status |= MxLWare603_OEM_ReadRegister(fe, CHIP_VERSION_REQ_REG, &readBack);
		mxlDevVerInfoPtr->chipVersion = (readBack & 0xFF); 

	//	printk("Chip ID = 0x%d, Version = 0x%d \n", mxlDevVerInfoPtr->chipId, 
	//		mxlDevVerInfoPtr->chipVersion);

		// Get MxLWare version infromation
		for (k = 0; k < MXL603_VERSION_SIZE; k++)
			mxlDevVerInfoPtr->mxlwareVer[k] = MxLWare603DrvVersion[k];
	}
	else 
		status = MXL_INVALID_PARAMETER;

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_ReqDevGPOStatus
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This API is used to get GPO pin's status information from
--|                 MxL603 tuner device.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_ReqDevGPOStatus(struct dvb_frontend *fe, 
													  MXL603_GPO_STATE_E* gpoStatusPtr)
{
	UINT8 status = MXL_SUCCESS;
	UINT8 regData = 0;

	//MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	if (gpoStatusPtr)
	{
		status = MxLWare603_OEM_ReadRegister(fe, GPO_SETTING_REG, &regData);

		// GPO1 bit<1:0>
		if ((regData & 0x01) == 0) *gpoStatusPtr = MXL603_GPO_AUTO_CTRL;
		else *gpoStatusPtr = (MXL603_GPO_STATE_E)((regData & 0x02) >> 1);
	}
	else
		status = MXL_INVALID_PARAMETER;

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgTunerMode
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This fucntion is used to configure MxL603 tuner's 
--|                 application modes like DVB-T, DVB-C, ISDB-T etc.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgTunerMode(struct dvb_frontend *fe, MXL603_TUNER_MODE_CFG_T tunerModeCfg)
												   
{
	UINT8 status = MXL_SUCCESS;
	UINT8 dfeRegData = 0;
	//struct MXL603_REG_CTRL_INFO_T* tmpRegTable;

////	printk(" Signal Mode = %d, IF Freq = %d, xtal = %d, IF Gain = %d", 
//		tunerModeCfg.signalMode,
//		tunerModeCfg.ifOutFreqinKHz,
//		tunerModeCfg.xtalFreqSel,
//		tunerModeCfg.ifOutGainLevel); 

	switch(tunerModeCfg.signalMode)
	{
	case MXL603_DIG_DVB_C:
	case MXL603_DIG_J83B:
	//	tmpRegTable = MxL603_DigitalDvbc;
		status = MxL603_Ctrl_ProgramRegisters(fe, MxL603_DigitalDvbc);

		if (tunerModeCfg.ifOutFreqinKHz < HIGH_IF_35250_KHZ)
		{
			// Low power
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_0, 0xFE);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_1, 0x10);
		}
		else
		{
			// High power
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_0, 0xD9);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_1, 0x16);
		}

		if (tunerModeCfg.xtalFreqSel == MXL603_XTAL_16MHz) dfeRegData = 0x0D;
		else if (tunerModeCfg.xtalFreqSel == MXL603_XTAL_24MHz) dfeRegData = 0x0E;
		else status |= MXL_INVALID_PARAMETER;

		status |= MxLWare603_OEM_WriteRegister(fe, DFE_CSF_SS_SEL, dfeRegData);

		break;

	case MXL603_DIG_ISDBT_ATSC:
		//tmpRegTable = MxL603_DigitalIsdbtAtsc;
		status = MxL603_Ctrl_ProgramRegisters(fe, MxL603_DigitalIsdbtAtsc);

		if (tunerModeCfg.ifOutFreqinKHz < HIGH_IF_35250_KHZ)
		{
			// Low power
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_0, 0xF9);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_1, 0x18);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_PWR, 0xF1);
		}
		else
		{
			// High power
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_0, 0xD9);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_1, 0x16);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_PWR, 0xB1);
		}

		if (MXL603_XTAL_16MHz == tunerModeCfg.xtalFreqSel) dfeRegData = 0x0D;
		else if (MXL603_XTAL_24MHz == tunerModeCfg.xtalFreqSel) dfeRegData = 0x0E;
		else status |= MXL_INVALID_PARAMETER;

		status |= MxLWare603_OEM_WriteRegister(fe, DFE_CSF_SS_SEL, dfeRegData);

		dfeRegData = 0;
		switch(tunerModeCfg.ifOutGainLevel)
		{
		case 0x09: dfeRegData = 0x44; break;
		case 0x08: dfeRegData = 0x43; break;
		case 0x07: dfeRegData = 0x42; break;
		case 0x06: dfeRegData = 0x41; break;
		case 0x05: dfeRegData = 0x40; break;
		default: break;
		}
		status |= MxLWare603_OEM_WriteRegister(fe, DFE_DACIF_GAIN, dfeRegData);

		break;

	case MXL603_DIG_DVB_T_DTMB:
		//tmpRegTable = MxL603_DigitalDvbt;
		status = MxL603_Ctrl_ProgramRegisters(fe, MxL603_DigitalDvbt);

		if (tunerModeCfg.ifOutFreqinKHz < HIGH_IF_35250_KHZ)
		{
			// Low power
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_0, 0xFE);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_1, 0x18);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_PWR, 0xF1);
		}
		else
		{
			// High power
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_0, 0xD9);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_CFG_1, 0x16);
			status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_IF_PWR, 0xB1);
		}

		if (MXL603_XTAL_16MHz == tunerModeCfg.xtalFreqSel) dfeRegData = 0x0D;
		else if (MXL603_XTAL_24MHz == tunerModeCfg.xtalFreqSel) dfeRegData = 0x0E;
		else status |= MXL_INVALID_PARAMETER;

		status |= MxLWare603_OEM_WriteRegister(fe, DFE_CSF_SS_SEL, dfeRegData);

		dfeRegData = 0;
		switch(tunerModeCfg.ifOutGainLevel)
		{
		case 0x09: dfeRegData = 0x44; break;
		case 0x08: dfeRegData = 0x43; break;
		case 0x07: dfeRegData = 0x42; break;
		case 0x06: dfeRegData = 0x41; break;
		case 0x05: dfeRegData = 0x40; break;
		default: break;
		}
		status |= MxLWare603_OEM_WriteRegister(fe, DFE_DACIF_GAIN, dfeRegData);
		break;

	default:
		status = MXL_INVALID_PARAMETER;
		break;
	}

	if (status == MXL_SUCCESS)  
	{
		// XTAL calibration
		status |= MxLWare603_OEM_WriteRegister(fe, XTAL_CALI_SET_REG, 0x00);   
		status |= MxLWare603_OEM_WriteRegister(fe, XTAL_CALI_SET_REG, 0x01);   

		// 50 ms sleep after XTAL calibration
		msleep(50);
	}

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgTunerAGC
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This function is used to configure AGC settings of MxL603
--|                 tuner device.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgTunerAGC(struct dvb_frontend *fe, MXL603_AGC_CFG_T agcCfg)
{
	UINT8 status = MXL_SUCCESS;
	UINT8 regData = 0; 

//	printk("%s, AGC sel = %d, attack point set = %d, Flip = %d \n", 
//		__FUNCTION__, 
//		agcCfg.agcType,
//		agcCfg.setPoint, 
//		agcCfg.agcPolarityInverstion);

	if ((agcCfg.agcPolarityInverstion <= MXL_ENABLE) && 
		(agcCfg.agcType <= MXL603_AGC_EXTERNAL))
	{
		// AGC selecton <3:2> and mode setting <0>
		status |= MxLWare603_OEM_ReadRegister(fe, AGC_CONFIG_REG, &regData); 
		regData &= 0xF2; // Clear bits <3:2> & <0>
		regData = (UINT8) (regData | (agcCfg.agcType << 2) | 0x01);
		status |= MxLWare603_OEM_WriteRegister(fe, AGC_CONFIG_REG, regData);

		// AGC set point <6:0>
		status |= MxLWare603_OEM_ReadRegister(fe, AGC_SET_POINT_REG, &regData);
		regData &= 0x80; // Clear bit <6:0>
		regData |= agcCfg.setPoint;
		status |= MxLWare603_OEM_WriteRegister(fe, AGC_SET_POINT_REG, regData);

		// AGC Polarity <4>
		status |= MxLWare603_OEM_ReadRegister(fe, AGC_FLIP_REG, &regData);
		regData &= 0xEF; // Clear bit <4>
		regData |= (agcCfg.agcPolarityInverstion << 4);
		status |= MxLWare603_OEM_WriteRegister(fe, AGC_FLIP_REG, regData);
	}
	else
		status = MXL_INVALID_PARAMETER;

	return(MXL_STATUS) status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgTunerLoopThrough
--| 
--| AUTHOR        : Mahendra Kondur, Dong Liu
--|
--| DATE CREATED  : 12/10/2011, 06/18/2012   
--|
--| DESCRIPTION   : This function is used to enable or disable Loop-Through
--|                 settings of MxL603 tuner device.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgTunerLoopThrough(struct dvb_frontend *fe, MXL_BOOL loopThroughCtrl)
{
	UINT8 status = MXL_SUCCESS, regData;

//	MxL_DLL_DEBUG0("%s", __FUNCTION__); 

	if (loopThroughCtrl <= MXL_ENABLE)
	{
		status |= MxLWare603_OEM_WriteRegister(fe, PAGE_CHANGE_REG, 0x01);

		status |= MxLWare603_OEM_ReadRegister(fe, DIG_ANA_GINJO_LT_REG, &regData);

		if (loopThroughCtrl == MXL_ENABLE)
			regData |= 0x10;  // Bit<4> = 1       
		else
			regData &= 0xEF;  // Bit<4> = 0  
		status |= MxLWare603_OEM_WriteRegister(fe, DIG_ANA_GINJO_LT_REG, regData);

		status |= MxLWare603_OEM_WriteRegister(fe, PAGE_CHANGE_REG, 0x00);
	}
	else
		status = MXL_INVALID_PARAMETER;

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgTunerChanTune
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This API configures RF channel frequency and bandwidth. 
--|                 Radio Frequency unit is Hz, and Bandwidth is in MHz units.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgTunerChanTune(struct dvb_frontend *fe, MXL603_CHAN_TUNE_CFG_T chanTuneCfg)
													   
{
	UINT64 frequency;
	UINT32 freq = 0;
	UINT8 status = MXL_SUCCESS;
	UINT8 regData = 0;
	UINT8 agcData = 0;
	UINT8 dfeTuneData = 0;
	UINT8 dfeCdcData = 0;

//	printk("%s, signal type = %d, Freq = %d, BW = %d, Xtal = %d \n",  
//		__FUNCTION__,
//		chanTuneCfg.signalMode, 
//		chanTuneCfg.freqInHz, 
//		chanTuneCfg.bandWidth, 
//		chanTuneCfg.xtalFreqSel);

	// Abort Tune
	status |= MxLWare603_OEM_WriteRegister(fe, START_TUNE_REG, 0x00); 

	if (chanTuneCfg.startTune == MXL_ENABLE)
	{
		if (chanTuneCfg.signalMode <= MXL603_DIG_J83B) 
		{
			// RF Frequency VCO Band Settings 
			if (chanTuneCfg.freqInHz < 700000000) 
			{
				status |= MxLWare603_OEM_WriteRegister(fe, 0x7C, 0x1F);
				if ((chanTuneCfg.signalMode == MXL603_DIG_DVB_C) || (chanTuneCfg.signalMode == MXL603_DIG_J83B)) 
					regData = 0xC1;
				else
					regData = 0x81;

			}
			else 
			{
				status |= MxLWare603_OEM_WriteRegister(fe, 0x7C, 0x9F);
				if ((chanTuneCfg.signalMode == MXL603_DIG_DVB_C) || (chanTuneCfg.signalMode == MXL603_DIG_J83B)) 
					regData = 0xD1;
				else
					regData = 0x91;

			}

			status |= MxLWare603_OEM_WriteRegister(fe, 0x00, 0x01);
			status |= MxLWare603_OEM_WriteRegister(fe, 0x31, regData);
			status |= MxLWare603_OEM_WriteRegister(fe, 0x00, 0x00);

			// Bandwidth <7:0>
			switch(chanTuneCfg.bandWidth)
			{
			case MXL603_CABLE_BW_6MHz:
			case MXL603_CABLE_BW_7MHz:
			case MXL603_CABLE_BW_8MHz:
			case MXL603_TERR_BW_6MHz:
			case MXL603_TERR_BW_7MHz:
			case MXL603_TERR_BW_8MHz:
				status |= MxLWare603_OEM_WriteRegister(fe, CHAN_TUNE_BW_REG, (UINT8)chanTuneCfg.bandWidth);

				// Frequency
				frequency = chanTuneCfg.freqInHz;

				/* Calculate RF Channel = DIV(64*RF(Hz), 1E6) */
				frequency *= 64;
				freq = (UINT32)(frequency / 1000000); 

				// Set RF  
				status |= MxLWare603_OEM_WriteRegister(fe, CHAN_TUNE_LOW_REG, (UINT8)(freq & 0xFF));
				status |= MxLWare603_OEM_WriteRegister(fe, CHAN_TUNE_HI_REG, (UINT8)((freq >> 8 ) & 0xFF));
				break;

			default:
				status |= MXL_INVALID_PARAMETER;
				break;
			}

			// Power up tuner module
			status |= MxLWare603_OEM_WriteRegister(fe, TUNER_ENABLE_REG, 0x01);

			// Start Sequencer settings
			status |= MxLWare603_OEM_WriteRegister(fe, PAGE_CHANGE_REG, 0x01); 
			status |= MxLWare603_OEM_ReadRegister(fe, DIG_ANA_GINJO_LT_REG, &regData);
			status |= MxLWare603_OEM_WriteRegister(fe, PAGE_CHANGE_REG, 0x00); 

			status |= MxLWare603_OEM_ReadRegister(fe, 0xB6, &agcData);
			status |= MxLWare603_OEM_WriteRegister(fe, PAGE_CHANGE_REG, 0x01); 
			status |= MxLWare603_OEM_ReadRegister(fe, 0x60, &dfeTuneData);
			status |= MxLWare603_OEM_ReadRegister(fe, 0x5F, &dfeCdcData);

			// Check if LT is enabled
			if ((regData & 0x10) == 0x10)
			{
				// dfe_agc_auto = 0 & dfe_agc_rf_bo_w = 14
				agcData &= 0xBF;
				agcData |= 0x0E;

				// dfe_seq_tune_rf1_bo = 14
				dfeTuneData &= 0xC0;
				dfeTuneData |= 0x0E;

				// dfe_seq_cdc_rf1_bo = 14
				dfeCdcData &= 0xC0;
				dfeCdcData |= 0x0E;
			}
			else
			{
				// dfe_agc_auto = 1 & dfe_agc_rf_bo_w = 0
				agcData |= 0x40;
				agcData &= 0xC0;

				// dfe_seq_tune_rf1_bo = 55
				dfeTuneData &= 0xC0;
				dfeTuneData |= 0x37;

				// dfe_seq_cdc_rf1_bo = 55
				dfeCdcData &= 0xC0;
				dfeCdcData |= 0x37;
			}

			status |= MxLWare603_OEM_WriteRegister(fe, 0x60, dfeTuneData); 
			status |= MxLWare603_OEM_WriteRegister(fe, 0x5F, dfeCdcData); 
			status |= MxLWare603_OEM_WriteRegister(fe, PAGE_CHANGE_REG, 0x00); 
			status |= MxLWare603_OEM_WriteRegister(fe, 0xB6, agcData); 

			// Bit <0> 1 : start , 0 : abort calibrations
			status |= MxLWare603_OEM_WriteRegister(fe, START_TUNE_REG, 0x01); 

			// Sleep 15 ms
			msleep(15);

			// dfe_agc_auto = 1 
			agcData = (agcData | 0x40);
			status |= MxLWare603_OEM_WriteRegister(fe, 0xB6, agcData); 

		}
		else
			status = MXL_INVALID_PARAMETER;
	}

	return (MXL_STATUS)status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_CfgTunerIFOutParam
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This function is used to configure IF out settings of MxL603 
--|                 tuner device.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_CfgTunerIFOutParam(struct dvb_frontend *fe,  MXL603_IF_OUT_CFG_T ifOutCfg)
{
	UINT16 ifFcw;
	UINT8 status = MXL_SUCCESS;
	UINT8 readData = 0;
	UINT8 control = 0;

//	printk("%s, Manual set = %d \n", __FUNCTION__, ifOutCfg.manualFreqSet); 

	//Test only 
	MxLWare603_OEM_WriteRegister(fe, 0x10, 0x99);
	MxLWare603_OEM_ReadRegister(fe, 0x10, &readData);
//	printk("\n ----------- test Tuner I2C read out = 0x%x [ if 0x99, I2C OK!]-------------\n", readData); 

	// Read back register for manual IF Out 
	status = MxLWare603_OEM_ReadRegister(fe, IF_FREQ_SEL_REG, &readData);

	if (ifOutCfg.manualFreqSet == MXL_ENABLE)
	{
		printk("%s, IF Freq = %d \n", __FUNCTION__, ifOutCfg.manualIFOutFreqInKHz); 

		// IF out manual setting : bit<5>
		readData |= 0x20;
		status = MxLWare603_OEM_WriteRegister(fe, IF_FREQ_SEL_REG, readData);

		// Manual IF freq set
		ifFcw = (UINT16)(ifOutCfg.manualIFOutFreqInKHz * 8192 / 216000);
		control = (ifFcw & 0xFF); // Get low 8 bit 
		status |= MxLWare603_OEM_WriteRegister(fe, IF_FCW_LOW_REG, control); 

		control = ((ifFcw >> 8) & 0x0F); // Get high 4 bit 
		status |= MxLWare603_OEM_WriteRegister(fe, IF_FCW_HIGH_REG, control);
	}
	else if (ifOutCfg.manualFreqSet == MXL_DISABLE)
	{
		// bit<5> = 0, use IF frequency from IF frequency table  
		readData &= 0xC0;

		// IF Freq <4:0>
		readData |= ifOutCfg.ifOutFreq;
		status |= MxLWare603_OEM_WriteRegister(fe, IF_FREQ_SEL_REG, readData);
	}
	else
		status |= MXL_INVALID_PARAMETER;

	if (status == MXL_SUCCESS)
	{
		// Set spectrum invert, gain level and IF path 
		// Spectrum invert indication is bit<7:6>
		if (ifOutCfg.ifInversion <= MXL_ENABLE)
		{
			control = 0;
			if (MXL_ENABLE == ifOutCfg.ifInversion) control = 0x3 << 6;

			// Gain level is bit<3:0> 
			control += (ifOutCfg.gainLevel & 0x0F);
			control |= (0x20); // Enable IF out
			status |= MxLWare603_OEM_WriteRegister(fe, IF_PATH_GAIN_REG, control);
		} 
		else
			status |= MXL_INVALID_PARAMETER;
	}

	return(MXL_STATUS) status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_ReqTunerAGCLock
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This function returns AGC Lock status of MxL603 tuner.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_ReqTunerAGCLock(struct dvb_frontend *fe, MXL_BOOL* agcLockStatusPtr)
{
	 MXL_STATUS status = MXL_SUCCESS;
	UINT8 regData = 0;
	 MXL_BOOL lockStatus = MXL_UNLOCKED;

	if (agcLockStatusPtr)
	{
		status = MxLWare603_OEM_ReadRegister(fe, AGC_SAGCLOCK_STATUS_REG, &regData);  
		if ((regData & 0x08) == 0x08) lockStatus = MXL_LOCKED;

		*agcLockStatusPtr =  lockStatus;

		printk(" Agc lock = %d", (UINT8)*agcLockStatusPtr); 
	}
	else
		status = MXL_INVALID_PARAMETER;

	return status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_ReqTunerLockStatus
--| 
--| AUTHOR        : Mahendra Kondur
--|
--| DATE CREATED  : 12/10/2011  
--|
--| DESCRIPTION   : This function returns Tuner Lock status of MxL603 tuner.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_ReqTunerLockStatus(struct dvb_frontend *fe,  MXL_BOOL* rfLockPtr, 
														 	 MXL_BOOL* refLockPtr)
{
	MXL_STATUS status = MXL_SUCCESS;
	UINT8 regData = 0;
	MXL_BOOL rfLockStatus = MXL_UNLOCKED;
	MXL_BOOL refLockStatus = MXL_UNLOCKED;

	//  MxL_DLL_DEBUG0("%s", __FUNCTION__);

	if ((rfLockPtr) && (refLockPtr))
	{
		status = MxLWare603_OEM_ReadRegister(fe, RF_REF_STATUS_REG, &regData);  

		if ((regData & 0x02) == 0x02) rfLockStatus = MXL_LOCKED;
		if ((regData & 0x01) == 0x01) refLockStatus = MXL_LOCKED;

		*rfLockPtr =  rfLockStatus;
		*refLockPtr = refLockStatus;
	}
	else
		status = MXL_INVALID_PARAMETER;

	return status;
}

/*------------------------------------------------------------------------------
--| FUNCTION NAME : MxLWare603_API_ReqTunerRxPower
--| 
--| AUTHOR        : Mahendra Kondur
--|                 Dong Liu 
--|
--| DATE CREATED  : 12/10/2011
--|                 06/18/2012
--|
--| DESCRIPTION   : This function returns RF input power in 0.01dBm.
--|
--| RETURN VALUE  : MXL_SUCCESS, MXL_INVALID_PARAMETER, MXL_FAILED
--|
--|---------------------------------------------------------------------------*/

MXL_STATUS MxLWare603_API_ReqTunerRxPower(struct dvb_frontend *fe, SINT16* rxPwrPtr)
{
	UINT8 status = MXL_SUCCESS;
	UINT8 regData = 0;
	UINT16 tmpData = 0;

	//  MxL_DLL_DEBUG0("%s", __FUNCTION__);

	if (rxPwrPtr)
	{
		// RF input power low <7:0>
		status = MxLWare603_OEM_ReadRegister(fe, RFPIN_RB_LOW_REG, &regData);
		tmpData = regData;

		// RF input power high <1:0>
		status |= MxLWare603_OEM_ReadRegister(fe, RFPIN_RB_HIGH_REG, &regData);
		tmpData |= (regData & 0x03) << 8;

		// Fractional last 2 bits
		*rxPwrPtr = (tmpData & 0x01FF) * 25;  //100 times dBm

		if (tmpData & 0x02) *rxPwrPtr += 50;;
		if (tmpData & 0x01) *rxPwrPtr += 25;
		if (tmpData & 0x0200) *rxPwrPtr -= 128*100;

		//printk(" Rx power = %d times of 0.01dBm \n", *rxPwrPtr);
	}
	else
		status = MXL_INVALID_PARAMETER;

	return (MXL_STATUS)status;
}


MXL_STATUS MXL603_init(struct dvb_frontend *fe)
{
	MXL_STATUS status; 
//	UINT8 devId;
	MXL_BOOL singleSupply_3_3V;
	MXL603_XTAL_SET_CFG_T xtalCfg;
	MXL603_IF_OUT_CFG_T ifOutCfg;
	MXL603_AGC_CFG_T agcCfg;
	MXL603_TUNER_MODE_CFG_T tunerModeCfg;
	MXL603_VER_INFO_T	mxl603Version;
	
	MxLWare603_API_ReqDevVersionInfo(fe, &mxl603Version);


	/* If OEM data is not required, customer should treat devId as 
	I2C slave Address */
//	devId = MXL603_I2C_ADDR;

	//Step 1 : Soft Reset MxL603
	status = MxLWare603_API_CfgDevSoftReset(fe);
	if (status != MXL_SUCCESS)
	{
		printk("Error! MxLWare603_API_CfgDevSoftReset\n");    
	}

	//Step 2 : Overwrite Default
	/*Parameter : singleSupply_3_3V
	- Enable :  Single power supply to Tuner (3.3v only;  3.3v -> 1.8V tuner internally inverts ) 
	- Disable : Dual power supply to Tuner (3.3v+1.8v; internal regulator be bypassed) 
	\A1\EF If set wrongly toward hardware layout, Tuner will loose control of AGC(at least) 
	*/
	singleSupply_3_3V = MXL_ENABLE; //MXL_DISABLE;
	status = MxLWare603_API_CfgDevOverwriteDefaults(fe, singleSupply_3_3V);
	if (status != MXL_SUCCESS)
	{
		printk("Error! MxLWare603_API_CfgDevOverwriteDefaults\n");    
	}

	//Step 3 : XTAL Setting 

	/* Single XTAL for tuner and demod sharing*/
	xtalCfg.xtalFreqSel = MXL603_XTAL_24MHz;
	xtalCfg.xtalCap = 31; //Pls. set this based on the XTAL's SPEC : the matching capacitence to output accurate Clock
	xtalCfg.clkOutEnable = MXL_ENABLE;
	xtalCfg.clkOutDiv = MXL_DISABLE;
	xtalCfg.clkOutExt = MXL_DISABLE;
	xtalCfg.singleSupply_3_3V = MXL_ENABLE;
	xtalCfg.XtalSharingMode = MXL_DISABLE;
	status = MxLWare603_API_CfgDevXtal(fe, xtalCfg);
	if (status != MXL_SUCCESS)
	{
		printk("Error! MxLWare603_API_CfgDevXtal\n");    
	}

	//Step 4 : IF Out setting
	//IF freq set, should match Demod request 
	ifOutCfg.ifOutFreq = MXL603_IF_5MHz; //we suggest 5Mhz for ATSC MN88436 

	ifOutCfg.ifInversion = MXL_DISABLE;
	ifOutCfg.gainLevel = 11;
	ifOutCfg.manualFreqSet = MXL_DISABLE;
	ifOutCfg.manualIFOutFreqInKHz = 0;
	status = MxLWare603_API_CfgTunerIFOutParam(fe, ifOutCfg);
	if (status != MXL_SUCCESS)
	{
		printk("Error! MxLWare603_API_CfgTunerIFOutParam\n");    
	}

	//Step 5 : AGC Setting
	//agcCfg.agcType = MXL603_AGC_SELF; //if you doubt DMD IF-AGC part, pls. use Tuner self AGC instead.
	agcCfg.agcType = MXL603_AGC_SELF;
	agcCfg.setPoint = 66;
	agcCfg.agcPolarityInverstion = MXL_DISABLE;
	status = MxLWare603_API_CfgTunerAGC(fe, agcCfg);
	if (status != MXL_SUCCESS)
	{
		printk("Error! MxLWare603_API_CfgTunerAGC\n");    
	}

	//Step 6 : Application Mode setting
	tunerModeCfg.signalMode = MXL603_DIG_ISDBT_ATSC;//MXL603_DIG_DVB_T_DTMB;

	//IF freq set, should match Demod request 
	tunerModeCfg.ifOutFreqinKHz = 5000;


	/* Single XTAL for tuner and demod sharing*/
	tunerModeCfg.xtalFreqSel = MXL603_XTAL_24MHz;
	tunerModeCfg.ifOutGainLevel = 11;
	status = MxLWare603_API_CfgTunerMode(fe, tunerModeCfg);
	if (status != MXL_SUCCESS)
	{
		printk("##### Error! pls. make sure return value no problem, otherwise, it will cause Tuner unable to unlock signal #####\n");   
		printk("Error! MxLWare603_API_CfgTunerMode\n");    
	}




	// To Change Channel, GOTO Step #7

	// To change Application mode settings, GOTO Step #6

	return status;
}



MXL_STATUS Mxl603SetFreqBw(struct dvb_frontend *fe,UINT32 freq)
{
	MXL_STATUS status; 
//	UINT8 devId;
	MXL_BOOL refLockPtr;
	MXL_BOOL rfLockPtr;
	MXL603_CHAN_TUNE_CFG_T chanTuneCfg;
	UINT32 rf;
//	devId = MXL603_I2C_ADDR;
	
	//Step 7 : Channel frequency & bandwidth setting
//	printk("freq=%d",freq);
	if(freq>1000000)rf=freq;
	else if(freq>1000)rf=freq*1000;
	else
		rf=freq*1000000;
	
	
	chanTuneCfg.bandWidth = MXL603_TERR_BW_6MHz;
	chanTuneCfg.freqInHz = rf;
	if(param.system == DMD_E_ATSC)
	chanTuneCfg.signalMode = MXL603_DIG_ISDBT_ATSC;
	else
	chanTuneCfg.signalMode = MXL603_DIG_J83B;
	
	chanTuneCfg.startTune = MXL_START_TUNE;
	chanTuneCfg.xtalFreqSel =MXL603_XTAL_16MHz;

	//chanTuneCfgis global struct. 
	status = MxLWare603_API_CfgTunerChanTune(fe, chanTuneCfg);
	if (status != MXL_SUCCESS)
	{
		printk("Error! MxLWare603_API_CfgTunerChanTune\n");    
	}

	// Wait 15 ms 
	msleep(15);

	// Read back Tuner lock status
	status = MxLWare603_API_ReqTunerLockStatus(fe, &rfLockPtr, &refLockPtr);
	if (status == MXL_TRUE)
	{
		if (MXL_LOCKED == rfLockPtr && MXL_LOCKED == refLockPtr)
		{
			printk("Tuner locked\n"); //If system runs into here, it mean that Tuner locked and output IF OK!!
		}
		else
			printk("Tuner unlocked\n");
	}
	return status; 
}

DMD_ERROR_t  DMD_open(  DMD_PARAMETER_t* param)
{
	int i;

	param->devid = 0;
	param->system= DMD_E_ATSC;
	/* Initialize Parameter Variable */
	for(i=0;i<DMD_INFORMATION_MAX;i++)
	{
		param->info[i] = 0;		//NOT_DEFINED 
	}
	param->bw		= DMD_E_BW_6MHZ;
	param->freq		= 0;
	param->funit	= DMD_E_KHZ;

	//ts output method select 
	param->ts_out = DMD_E_TSOUT_PARALLEL_BRTG_MODE;

	//troy.wang, 20120801, for customer to pass test in lab.( SPEC : A74-2010 )
	param->echo_set = DMD_E_ENHANCE_MINUS_ECHO_DELAY_NO_SIDEEFFECT;


	return DMD_E_OK;
}

DMD_u8_t DMD_BANK_MAIN(DMD_u8_t id)
{
	DMD_u8_t	ret;

	switch(id)
	{
	case 0: ret = 0x18; break;
	case 1: ret = 0x19; break;
	case 2: ret = 0x1A; break;
	case 3: ret = 0x1B; break;
	default: ret = 0x18;break;
	}
	return ret;
}

DMD_u8_t DMD_BANK_USR(DMD_u8_t id)
{
	DMD_u8_t	ret;

	switch(id)
	{
		case 0: ret = 0x10; break;
		case 1: ret = 0x11; break;
		case 2: ret = 0x12; break;
		case 3: ret = 0x13; break;
		default: ret = 0x10;break;
	}
	return ret;
}

/* **************************************************** */
/*!	Get Register Settings for Broadcast system */
/* **************************************************** */
DMD_ERROR_t DMD_device_init(struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	DMD_ERROR_t	ret;
	ret = DMD_E_OK;

//	DMD_send_registers( DMD_I2C_SLAVE[param->devid] , DMD_REG_ATSC );
	switch( param->system ){
			case DMD_E_ATSC:
			DMD_send_registers(fe, DMD_I2C_SLAVE[param->devid] , DMD_REG_ATSC );
			//DMD_device_load_pseq( param ); //troy.wangyx masked, 20120801, only need do once, in initialization. 
			break;
		case DMD_E_QAMB_64QAM:
			DMD_send_registers(fe, DMD_I2C_SLAVE[param->devid] , DMD_REG_QAM_B_64QAM );
			//DMD_device_load_pseq( param );
			break;
		case DMD_E_QAMB_256QAM:
			DMD_send_registers(fe, DMD_I2C_SLAVE[param->devid] , DMD_REG_QAM_B_256QAM );
			//DMD_device_load_pseq( param );
			break;
		default:
			//Not Support
			printk( "ERROR : Not Supported System");
			ret = DMD_E_ERROR;
	}


	return ret;
}


DMD_ERROR_t DMD_device_load_pseq( struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	DMD_ERROR_t ret = DMD_E_OK;
	DMD_u8_t	data;
	DMD_u32_t	i;
	/* Load PSEQ Program */
	ret  = DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_PSEQSET , 0x03 );
	for(i=0;i<MN88436_REG_AUTOCTRL_SIZE;i++)
		ret = DMD_I2C_Write( fe ,DMD_BANK_MAIN(param->devid), DMD_MAIN_PSEQPRG  , MN88436_REG_AUTOCTRL[i] );

	/* Check Parity bit */
	ret = DMD_I2C_Read(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_PSEQSET , &data);
	if( data & 0x20 ){
		printk( "ERROR: PSEQ Parity" );
		ret = DMD_E_ERROR;
	}
	else
	{
		ret = DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_PSEQSET  , 0x00 );
	}
	return ret;
}

/* **************************************************** */
/*!	Set Register setting for I2C communication mode between DMD  and Tuner*/
/* **************************************************** */
//Troy.wangyx 20120801, set once is enough 
DMD_ERROR_t	DMD_device_set_TCB_mode(struct dvb_frontend* fe, DMD_PARAMETER_t* param)
{
	DMD_ERROR_t	ret;
	DMD_u8_t	bank;
	DMD_u8_t	tcbcom,tcbadr,tcbset;

	ret = DMD_E_ERROR;

	bank = DMD_BANK_MAIN(param->devid);
	tcbcom=DMD_MAIN_TCBCOM;
	tcbadr=DMD_MAIN_TCBADR;
	tcbset=DMD_MAIN_TCBSET;

	/* Set TCB Through Mode */
	ret  = DMD_I2C_MaskWrite(fe, bank , tcbset , 0x7f , 0x53 );
	ret = DMD_I2C_Write(fe, bank , tcbadr , 0x00 );

	return ret;

}



/* Set TS parallel or serial mode. If you want to set to parallel, make sure your hardware connection no problem */
DMD_ERROR_t DMD_set_ts_output(struct dvb_frontend* fe, DMD_PARAMETER_t* param,  DMD_TSCLK_POLARITY ts_clk_polarity )
{  
	switch(param->ts_out)
	{
		case DMD_E_TSOUT_PARALLEL_BRTG_MODE:
			//TS parallel	
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0xc1 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xff );//troy.wang, 121010, for parallel data setting
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x01 );

			break;
		
		case DMD_E_TSOUT_PARALLEL_SMOOTH_MODE:
			//TS parallel conventional mode : smooth 
			DMD_I2C_Write(fe,DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0x01 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xff );//troy.wang, 121010, for parallel data setting
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x00 ); //address : 0x01
			break;
			
		case DMD_E_TSOUT_PARALLEL_BURST_GATED_MODE:
			//TS parallel conventional mode : burst(gated mode)
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0x01 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xff );//troy.wang, 121010, for parallel data setting
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x02 ); 
			break;
		
		case DMD_E_TSOUT_PARALLEL_BURST_CONTINUOUS_MODE:
			//TS parallel conventional mode : burst(continous mode)
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0x01 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xff );//troy.wang, 121010, for parallel data setting
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x0a ); 
			break;
		
		case DMD_E_TSOUT_SERIAL_BRTG_MODE:					
			//TS serial BRTG mode 
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0xc0 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xC0 ); //set error output
			break;
		
		case DMD_E_TSOUT_SERIAL_SMOOTH_MODE:
			//TS serial conventional mode : smooth 
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0x00 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xC0 ); //set error output
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x00 ); //address : 0x01
			break;
		
		case DMD_E_TSOUT_SERIAL_BURST_GATED_MODE:
			//TS serial conventional mode : burst(gated mode)
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0x00 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xC0 ); //set error output
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x02 ); 
			break;
		
		case DMD_E_TSOUT_SERIAL_BURST_CONTINUOUS_MODE:
			//TS serial conventional mode : burst(continous mode)
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET2 , 0x00 );
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_GPSET1 , 0xC0 ); //set error output
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_CPOSET1 , 0x0a ); 
			break;
			
		default:
			return DMD_E_ERROR;

	}
		if (ts_clk_polarity == DMD_E_TSCLK_POLARITY_INVERSE)
		{		
			if (param->ts_out & 0x10) //serial clk
			{
				DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_INVSET, 0x01 );
			}
			else //parallel clk
			{
				DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_INVSET, 0x02 );
			}
		}
	return DMD_E_OK;
}

/* **************************************************** */
/*! Soft Reset */
/* **************************************************** */
DMD_ERROR_t DMD_device_reset(struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	DMD_ERROR_t	ret;
	switch( param->system ){
		case DMD_E_ATSC:
		case DMD_E_QAMB_64QAM:
		case DMD_E_QAMB_256QAM:
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_RSTSET1 , 0x77);
			ret = DMD_E_OK;
			break;
		default:
			ret = DMD_E_ERROR;
			break;
	}

	return ret;
}

DMD_ERROR_t DMD_device_post_tune(struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	DMD_device_reset(fe,param);
	return DMD_E_OK;
}

DMD_ERROR_t DMD_lock(struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	DMD_ERROR_t	ret = DMD_E_OK;
	DMD_u8_t	rd = 0;
	DMD_u32_t	lockstatus = 0;
	switch( param->system ){
		case DMD_E_ATSC:
		case DMD_E_QAMB_64QAM:
		case DMD_E_QAMB_256QAM:
			DMD_I2C_Read(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_STSMON1	 , &rd );
			rd &= 1;
			if( rd ) lockstatus = 1;
			break;
		default:
			//Not Support
				printk( "ERROR : Not Supported System");
				ret = DMD_E_ERROR;
	}

	param->info[DMD_E_INFO_STATUS] = rd;
	if( lockstatus )
	{
		param->info[DMD_E_INFO_LOCK] = DMD_E_LOCKED;
	} 
	else if( param->info[DMD_E_INFO_LOCK] == DMD_E_LOCKED )
	{
		param->info[DMD_E_INFO_LOCK] = DMD_E_LOCK_ERROR;
	}
	return ret;
}

DMD_ERROR_t DMD_scan_vq(struct dvb_frontend* fe, DMD_PARAMETER_t *param )
{
	DMD_u32_t	st;
	DMD_u32_t	now;
	DMD_u32_t	timeout = 1500 ;
	DMD_u8_t	rd;
	DMD_ERROR_t	ret = DMD_E_ERROR;
	param->info[DMD_E_INFO_LOCK] = DMD_E_LOCK_ERROR;	
	int i=0;
	//timeout setting & etc.
	switch( param->system )
	{
	case DMD_E_ATSC:
		timeout = 650;
		break;
	default:
		timeout = 2000;
		break;
	}
	
	for(i=0;i<160;i++)
	{
		DMD_I2C_Read(fe, DMD_BANK_MAIN(param->devid)  ,DMD_MAIN_STSMON1	 , &rd );
		//VQ LOCK
		if( rd & 0x1 )
		{
			param->info[DMD_E_INFO_LOCK] = DMD_E_LOCKED;	
			ret = DMD_E_OK;
			printk("Singal LOCK.");
			break;
		}
		msleep(2);			//wait 1ms
		
	}

	return ret;
}

DMD_ERROR_t DMD_device_scan(struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	DMD_ERROR_t	ret = DMD_E_ERROR;
	switch( param->system )
	{
		case DMD_E_ATSC:
		case DMD_E_QAMB_64QAM:
		case DMD_E_QAMB_256QAM:
			ret = DMD_scan_vq(fe ,param);
			break;
		default:
			break;
	}
	return ret;
}
DMD_ERROR_t	DMD_device_set_system(struct dvb_frontend* fe, DMD_PARAMETER_t* param){
	DMD_ERROR_t	ret;
	ret = DMD_E_OK;

	//Register transfer
	switch( param->system ){
		case DMD_E_ATSC:
			DMD_send_registers(fe, DMD_I2C_SLAVE[param->devid] , DMD_REG_ATSC );
			//DMD_device_load_pseq( param ); //troy.wangyx masked, 20120801, only need do once, in initialization. 
			break;
		case DMD_E_QAMB_64QAM:
			DMD_send_registers(fe, DMD_I2C_SLAVE[param->devid] , DMD_REG_QAM_B_64QAM );
			//DMD_device_load_pseq( param );
			break;
		case DMD_E_QAMB_256QAM:
			DMD_send_registers(fe, DMD_I2C_SLAVE[param->devid] , DMD_REG_QAM_B_256QAM );
			//DMD_device_load_pseq( param );
			break;
		default:
			//Not Support
			printk( "ERROR : Not Supported System");
			ret = DMD_E_ERROR;
	}

	return ret;

}
DMD_ERROR_t DMD_device_set_echo_enhance(struct dvb_frontend* fe,DMD_PARAMETER_t* param, DMD_ECHO_PERFORMANCE_SET echo_out )
{    
	switch(echo_out)
       {
	       case DMD_E_ENHANCE_MINUS_ECHO_DELAY_DEFAULT:
			// DMD_MAIN_VEQSET2	0x80   |  field test passed result	
			DMD_I2C_Write( fe,DMD_BANK_MAIN(param->devid) , DMD_MAIN_VEQSET2 , 0x80 );
			break;
		case DMD_E_ENHANCE_MINUS_ECHO_DELAY_NO_SIDEEFFECT:
			//DMD_MAIN_VEQSET2		0xE0    | Lab test. enhance MINUS echo dalay performance, no side effect
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_VEQSET2 , 0xE0 );
			break;
		case DMD_E_ENHANCE_MINUS_ECHO_DELAY_HAS_SIDEEFFECT:
			//DMD_MAIN_VEQSET2		0xF0    |	FIFOSET:0xE3 Lab test. enhance MINUS echo dalay performance, has side effect on CCI(NTSC interface)
			DMD_I2C_Write(fe, DMD_BANK_MAIN(param->devid) , DMD_MAIN_VEQSET2 , 0xF0 );
			break;
	default:
		return DMD_E_ERROR;
	}
	return DMD_E_OK;
}
DMD_ERROR_t DMD_set_system( struct dvb_frontend* fe,DMD_PARAMETER_t* param )
{

		if( DMD_device_set_system(fe, param ) == DMD_E_ERROR )
		{
			printk("ERROR:device set system");
			return DMD_E_ERROR;
		}
		
		/* '11/08/29 : OKAMOTO	Select TS output. */
		if( DMD_set_ts_output(fe,param, param->ts_out ) == DMD_E_ERROR ){
			printk("ERROR:set ts output");
			return DMD_E_ERROR;
		}
		
		/* 20120801, troy, set echo performance */
		if (DMD_device_set_echo_enhance(fe, param, param->echo_set) == DMD_E_ERROR )
		{
			printk("===== ERROR: DMD set echo performace =====\r\n");
			return DMD_E_ERROR;
		}
		

	return DMD_E_OK;
}
DMD_ERROR_t DMD_init( struct dvb_frontend* fe, DMD_PARAMETER_t* param )
{
	/*IF use DMD to repeat I2C cmd, firstly initializing DMD is better. Troy.wangyx, 120801*/
	/* Demodulator LSI Initialize */
	if( DMD_device_init(fe, param ) == DMD_E_ERROR )
	{
		printk( "ERROR: DMD Initialize" );
		return DMD_E_ERROR;
	}
	/* Auto Control Sequence Transfer */
	if( DMD_device_load_pseq(fe, param ) == DMD_E_ERROR )
	{
		printk( "ERROR: DMD Load Autocontrol" );
		return DMD_E_ERROR;
	}

	/* 20120801, troy, set TCB control mode : Through mode */
	if (DMD_device_set_TCB_mode( fe,param ) == DMD_E_ERROR )
	{
		printk( "ERROR: DMD set tcb I2C mode" );
		return DMD_E_ERROR;
	}


	return DMD_E_OK;
}


static int MNDMD_init(struct dvb_frontend* fe)
{	
	struct mndmd_state *state = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	DMD_open(&param);
	DMD_init( fe,&param);
	MXL603_init(fe);
	DMD_set_ts_output(fe,&param,DMD_E_TSCLK_POLARITY_NORMAL);

	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_error.len = 1;
	c->post_bit_error.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_count.len = 1;
	c->post_bit_count.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	return 0;
}

static int DMD_set_parameters(struct dvb_frontend* fe)
{
	int ret;
	struct mndmd_state* state = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	switch (c->modulation) {
	case VSB_8:
		param.system = DMD_E_ATSC;
		break;
	case QAM_64:
		param.system = DMD_E_QAMB_64QAM;
		break;
	case QAM_256:
	  param.system = DMD_E_QAMB_256QAM;
		break;
	default:
		return -EINVAL;
	}
	DMD_set_system(fe,&param);
	
	Mxl603SetFreqBw(fe, c->frequency);
	msleep(2);
	DMD_device_post_tune(fe, &param );
	
	/* Call Lock/SYNC Status Judgement */
	 DMD_device_scan(fe, &param );

	return 0;
}

static int DMD_get_parameters(struct dvb_frontend* fe,
				 struct dtv_frontend_properties *c)
{
	struct mndmd_state* state = fe->demodulator_priv;

	return 0;
}

static int DMD_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	struct mndmd_state* state = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	DMD_u32_t	lockstatus = 0;
	DMD_u8_t	rd = 0;
	DMD_u32_t  x,y,val;
	s16 rfpower;
	DMD_I2C_Read(fe, DMD_BANK_MAIN(0) , DMD_MAIN_STSMON1 , &rd );
	rd &= 1;
	if( rd ) lockstatus = 1;

	if (lockstatus) /* Receiver Lock */
		*status = FE_HAS_SIGNAL|FE_HAS_CARRIER|FE_HAS_VITERBI|
			  FE_HAS_SYNC|FE_HAS_LOCK;
	else
		*status = FE_HAS_SIGNAL;


	MxLWare603_API_ReqTunerRxPower(fe,&rfpower);
	

	c->strength.len = 2;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = rfpower*10;

	c->strength.stat[1].scale = FE_SCALE_RELATIVE;
	c->strength.stat[1].uvalue = min(max(2*(rfpower/100+69),0),100);

	if(*status&FE_HAS_VITERBI){
	DMD_I2C_Read(fe, DMD_BANK_USR(0) , DMD_USR_CNMON1 , &rd );
	x = 0x100 * rd;
	DMD_I2C_Read(fe, DMD_BANK_USR(0) , DMD_USR_CNMON2 , &rd );
	x += rd;
	DMD_I2C_Read(fe, DMD_BANK_USR(0) , DMD_USR_CNMON3 , &rd );
	y = 0x100 * rd;
	DMD_I2C_Read(fe, DMD_BANK_USR(0) , DMD_USR_CNMON4 , &rd );
	y += rd;
	if( c->modulation == VSB_8 )
	{
		//after EQ
		val = 4634 - log10_easy( y );
		
	}
	else
	{
		if( y != 0  )
			val = log10_easy( (8*x) / y );
		else
			val = 0;

	}
	printk("cnr = %d",val);
	c->cnr.len = 2;
	c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
	c->cnr.stat[0].uvalue =  val*10;

	c->cnr.stat[1].scale = FE_SCALE_RELATIVE;
	c->cnr.stat[1].uvalue =min(max((val*10)/1000*24/10,0),100);
	}

	if(*status &FE_HAS_LOCK){
	DMD_u32_t	berr = 0 ,bit = 1;
	DMD_u8_t	rd;

	DMD_I2C_Write(fe,  DMD_BANK_USR(0) , DMD_USR_BERTSET1 , 0x40 );
	DMD_I2C_Write(fe,  DMD_BANK_USR(0) , DMD_USR_BERTSET2 , 0x0C );
	DMD_I2C_Read(fe,  DMD_BANK_USR(0) , DMD_USR_BERTSET1 , &rd );
	rd &= 0xfe;		//bit error mode
	DMD_I2C_Write(fe,  DMD_BANK_USR(0) , DMD_USR_BERTSET1 , rd );
	DMD_I2C_Read (fe,  DMD_BANK_USR(0) , DMD_USR_BERTSET2 , &rd );
	bit = (rd >> 2) & 0x7;
	if( c->modulation == VSB_8 )
		bit = (1 << (5+bit*2))*208*8;
	else
		bit = (1 << (5+bit*2))*127*7;
	DMD_I2C_Read (fe,  DMD_BANK_USR(0) , DMD_USR_BERMON1 , &rd );
	berr = rd * 65536;
	DMD_I2C_Read (fe,  DMD_BANK_USR(0) , DMD_USR_BERMON2 , &rd );
	berr += rd * 256;
	DMD_I2C_Read (fe,  DMD_BANK_USR(0) , DMD_USR_BERMON3 , &rd );
	berr += rd ;
	c->post_bit_error.len = 1;
	c->post_bit_error.stat[0].scale = FE_SCALE_COUNTER;
	c->post_bit_error.stat[0].uvalue = berr;
	c->post_bit_count.len = 1;
	c->post_bit_count.stat[0].scale = FE_SCALE_COUNTER;
	c->post_bit_count.stat[0].uvalue = berr;	
	}
	return 0;
}

static int DMD_tune(struct dvb_frontend *fe, bool re_tune,
	unsigned int mode_flags, unsigned int *delay, enum fe_status *status)
{
	struct mndmd_state* state = fe->demodulator_priv;
	*delay = HZ/5;
	if(re_tune){
       		int ret=DMD_set_parameters(fe);
		if (ret)
			return ret;
		}
	 
	return DMD_read_status(fe,status);
}
static int DMD_get_tune_settings(struct dvb_frontend* fe, struct dvb_frontend_tune_settings* fe_tune_settings)
{
	fe_tune_settings->min_delay_ms = 500;
	fe_tune_settings->step_size = 0;
	fe_tune_settings->max_drift = 0;

	return 0;
}

static void DMD_release(struct dvb_frontend* fe)
{
	struct mndmd_state* state = fe->demodulator_priv;
	
	kfree(state);
	
}

static int DMD_read_signal_strength(struct dvb_frontend* fe, u16* strength)
{
	/* Calculate Strength from SNR up to 35dB */
	/* Even though the SNR can go higher than 35dB, there is some comfort */
	/* factor in having a range of strong signals that can show at 100%   */

	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i=0;
	*strength = 0;
	for (i=0; i < p->strength.len; i++)
	{
		if (p->strength.stat[i].scale == FE_SCALE_RELATIVE)
			*strength = (u16)p->strength.stat[i].uvalue*655;
	}

	return 0;

}

static int DMD_read_snr(struct dvb_frontend* fe, u16* snr)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*snr = 0;
	for (i=0; i < p->cnr.len; i++){
		if (p->cnr.stat[i].scale == FE_SCALE_RELATIVE)
		  *snr = (u16)p->cnr.stat[i].uvalue*655;

	}
	return 0;
}

static int DMD_read_ber(struct dvb_frontend* fe, u32* ber)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;

	if ( p->post_bit_error.stat[0].scale == FE_SCALE_COUNTER &&
		p->post_bit_count.stat[0].scale == FE_SCALE_COUNTER )
		*ber = (u32)p->post_bit_count.stat[0].uvalue ? (u32)p->post_bit_error.stat[0].uvalue /
					(u32)p->post_bit_count.stat[0].uvalue : 0;

	return 0;
}

static int DMD_read_ucblocks(struct dvb_frontend* fe, u32* ucblocks)
{
	*ucblocks = 0;
	return 0;
}

static int DMD_sleep(struct dvb_frontend* fe)
{
	return 0;
}

static struct dvb_frontend_ops mndmd_ops = {
	.delsys = { SYS_ATSC, SYS_DVBC_ANNEX_B },
	.info = {
		.name			= "Panasonic MN88436 8VSB/QAM Frontend",
		.frequency_min_hz = 44* MHz,
		.frequency_max_hz = 1002 * MHz,
		.frequency_stepsize_hz	= 62500,
		.caps = FE_CAN_FEC_AUTO | FE_CAN_QAM_AUTO | FE_CAN_QAM_64 | FE_CAN_QAM_256 | FE_CAN_8VSB
	},

	.release = DMD_release,

	.init = MNDMD_init,
	.sleep = DMD_sleep,

	.set_frontend = DMD_set_parameters,
	.get_frontend = DMD_get_parameters,
	.get_tune_settings = DMD_get_tune_settings,
	.tune = DMD_tune,

	.read_status = DMD_read_status,
	.read_ber = DMD_read_ber,
	.read_signal_strength = DMD_read_signal_strength,
	.read_snr = DMD_read_snr,
	.read_ucblocks = DMD_read_ucblocks,
};


struct dvb_frontend* mndmd_attach(struct mndmd_config* config,
				    struct i2c_adapter* i2c)
{
	struct mndmd_state* state = NULL;

	/* Allocate memory for the internal state */
	state = kzalloc(sizeof(struct mndmd_state), GFP_KERNEL);
	if (state == NULL)
		return NULL;

	/* Setup the state */
	state->config = config;
	state->i2c = i2c;


	/* Create dvb_frontend */
	memcpy(&state->frontend.ops, &mndmd_ops, sizeof(struct dvb_frontend_ops));
	state->frontend.demodulator_priv = state;
	return &state->frontend;
}

EXPORT_SYMBOL(mndmd_attach);
MODULE_DESCRIPTION("mn88436 qamb atsc demodulator driver");
MODULE_AUTHOR("Georg Acher, Bob Liu, Igor liplianin");
MODULE_LICENSE("GPL");


