/*
** tsk_hrfs.h
** The Sleuth Kit
**
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the structures and function APIs for hrfs file system support.
 */

#ifndef _TSK_hrfs_H
#define _TSK_hrfs_H

#ifdef __cplusplus
extern "C" {
#endif

#define HRFS_FS_MAGIC       "WR_HRFS"
#define HRFS_MAGIC_OFF      3
#define HRFS_TOTALBLKSOFF   32   	// offset to total blocks
#define HRFS_MIN_BLOCK_SZ   9    	// as a power of 2
#define HRFS_MAX_BLOCK_SZ   16   	// as a power of 2
#define HRFS_FIRSTINO       2    	// first usable inode number
#define HRFS_ROOTINO        2    	// location of root directory inode 
#define HRFS_INODE_SZ       64   	// size of an inode
#define HRFS_MAXNAMLEN		252		// 252 bytes total for the file name
#define HRFS_MAXPATHLEN		4096		// IS THIS TRUE? NOT SURE
#define HRFS_NDADDR      	1		// number of direct addresses
#define HRFS_NIADDR      	3		// number of indirect addresses
#define HRFS_DENT_SZ		256 	// 4 for inode number and 252 for the filename
#define HRFS_ON_DISK_SB_LEN 96 
#define HRFS_FILE_CONTENT_LEN ((HRFS_NDADDR + HRFS_NIADDR) * sizeof(TSK_DADDR_T))

/*
 * directory entries
 */
typedef struct {
    uint8_t inode[4];       		// u32 			
    char name[HRFS_MAXNAMLEN];		// 252 chars
} hrfs_dentry;

/* MODE */
#define HRFS_IN_FMT		0xf000		// file type field
#define HRFS_IN_FIFO	0x1000		// fifo
#define HRFS_IN_CHR		0x2000		// character special
#define HRFS_IN_DIR		0x4000		// directory
#define HRFS_IN_BLK		0x6000		// block special
#define HRFS_IN_REG		0x8000		// regular
#define HRFS_IN_LNK		0xa000		// symbolic link
#define HRFS_IN_SHM		0xb000		// shared memory object
#define HRFS_IN_SOCK	0xc000		// socket

#define HRFS_IN_ISUID	0x0800		// set user id execution
#define HRFS_IN_ISGID	0x0400		// set group id execution
#define HRFS_IN_ISVTX	0x0200		// sticky bit
#define HRFS_IN_IRUSR	0x0100		// read permission, owner
#define HRFS_IN_IWUSR	0x0080		// write permission, owner
#define HRFS_IN_IXUSR	0x0040		// execute/search permission, owner
#define HRFS_IN_IRGRP	0x0020		// read permission, group
#define HRFS_IN_IWGRP	0x0010		// write permission, group
#define HRFS_IN_IXGRP	0x0008		// execute/search permission, group
#define HRFS_IN_IROTH	0x0004		// read permission, other
#define HRFS_IN_IWOTH	0x0002		// write permission, other
#define HRFS_IN_IXOTH	0x0001		// execute/search permission, other

//#define VX_ACCESSPERMS 	0x0777		// S_IRWXU|S_IRWXG|S_IRWXO
//#define VX_ALLPERMS 		0x7777		// S_ISUID|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
//#define VX_DEFFILEMODE 	0x0666		// S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


/*
 * Inode
 */
typedef struct {
    uint8_t i_size[8];				// u64 The size of the file 
	uint8_t i_generation[4];		// u32 # of times inode has been allocated
	uint8_t i_uid[4];				// u32 UID of value of the owner of the file
	uint8_t i_gid[4];				// u32 GID of value of the owner of the file
	uint8_t	i_nBlocks[4];			// u32 The number of blocks associated with inode
	uint8_t	i_pointers[4][4];		// u32*4 Direct & Indirect block references
	uint8_t i_nlink[2];				// u16 Number of hard links to file
	uint8_t i_mode[2];				// u16 Mode bits for file
	uint8_t	i_ctime[6];				// u8*6 The last time the file attributes (inode) were changed
	uint8_t	i_mtime[6];				// u8*6 The last time the file data was changed
	uint8_t	i_atime[6];				// u8*6 The last time the file data was accessed
	uint8_t	i_state;				// u8 State: free, allocated, to be deleted
	uint8_t	i_version;				// u8 Version format of on-disk inode
} hrfs_inode;

/*
 * Super Block
 */
typedef struct {
    char s_hrfs_id[8];              // u64 Identification of the HRFS file system: “WR_HRFS” 
	uint8_t s_sb_ctime[8];          // u64 Time at which the superblock was created (millis | epoch) 
	uint8_t s_ver_maj;              // u8  Major version number 
    uint8_t s_ver_min;      		// u8  Minor version number 
    uint8_t s_pow_block_size[2];	// u16 Block size as a power of 2 
    uint8_t s_total_blocks[4]; 		// u32 Total number of blocks in file system 
    uint8_t s_reserved_space[4];  	// u32 Size of the reserved space at the start of the media (always 1) 
    uint8_t s_inode_number[4];  	// u32 The number of inodes this file system instantiation has 
    uint8_t s_block_per_group[4];   // u32 Block group size 
    uint8_t s_data_space_size[4];   // u32 Data space size 
    uint8_t s_block_groups[4];      // u32 Number of block groups (always 1) 
    uint8_t s_free_space_bitmaps[8];// u32*2 1st and 2nd free space bitmap offsets 
    uint8_t s_free_inode_bitmaps[8];// u32*2 1st and 2nd free inode bitmap offsets 
    uint8_t s_inode_table[4];     	// u32 Inode table offset 
    uint8_t s_inode_journal[4];     // u32 Inode journal offset 
    uint8_t s_trans_maps[8]; 		// u32*2 1st and 2nd transaction map offsets 
    uint8_t s_trans_mrs[8];			// u32*2 1st and 2nd transaction master record offsets 
    uint8_t s_data_space[4];     	// u32 Data space offset (root directory) 
    uint8_t s_pad[4];    			// u32 Pad out structure 
    uint8_t s_crc[4];    			// u32 Superblock CRC 
} hrfs_sb;



/*
 * Structure of an hrfs file system handle.
 */
typedef struct {
    TSK_FS_INFO fs_info;			// super class
    hrfs_sb *fs;        			// super block

    tsk_lock_t lock;    			// lock protects bmap_buf, imap_buf 
    uint8_t *bmap_buf;  			// cached block allocation bitmap r/w shared - lock 
    uint8_t *imap_buf;  			// cached inode allocation bitmap r/w shared - lock 
    TSK_DADDR_T first_data_block;
    uint16_t inode_size;    		// size of each inode 

    //HRFS_JINFO *jinfo;
} HRFS_INFO;

#ifdef __cplusplus
}
#endif
#endif
