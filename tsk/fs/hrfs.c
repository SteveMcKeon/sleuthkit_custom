/*
** hrfs
** The Sleuth Kit
**
** Support for the hrfs file system - file name, meta data, file system layers
**
** Support built for the following tools. Others tools may work as a consequence.
**    mmls
**    mmstat
**    mmcat
**    fsstat
**    fls 
**    ifind
**    ffind
**    icat
**    ils
**    istat
 */
#include "tsk_fs_i.h"
#include "tsk_hrfs.h"
#include <stddef.h>
#include <time.h>
#include <ctype.h>
#include <string.h>

#define PRINT_MAPS 0

/*
 * \internal
 * hrfs_print_map - print a bitmap
 *
 * @param map The map to print
 * @param len The number of bytes to print
 */
static void hrfs_print_map(uint8_t * map, int len){
    int i;
    char buf[9] = "\0";
    for (i = 0; i <= len * 8; i++) {
        if (i > 0 && i % 8 == 0) {
            tsk_fprintf(stderr, "%s", buf);
            putc('|', stderr);
        }
        if (i > 0 && i % (8*8) == 0) {
            putc('\n', stderr);
        }
        buf[7 - i % 8] = isset(map, i) ? '1' : '.';
    }
}

/* 
 * hrfs_imap_load - look up a block of the inode bitmap & load into cache
 *
 * Note: This routine assumes &hrfs->lock is locked by the caller.
 *
 * @param hrfs
 * @param offset Block offset in the Free Inode Bitmap
 * 
 * return 0 on success and 1 on error
 */
static uint8_t hrfs_imap_load(HRFS_INFO * hrfs, int offset){
    TSK_FS_INFO *fs = (TSK_FS_INFO *) &hrfs->fs_info;
    unsigned int cnt;
    TSK_DADDR_T addr;

    /* Allocate the cache buffer and exit if map is already loaded */
    if (hrfs->imap_buf == NULL) {
        if ((hrfs->imap_buf = (uint8_t *) tsk_malloc(fs->block_size)) == NULL) {
            return 1;
        }
    }

    /*
    * Look up the inode allocation bitmap.
    */
    addr = tsk_getu32(fs->endian, hrfs->fs->s_free_inode_bitmaps);
    if (addr > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
        tsk_error_set_errstr
            ("hrfs_imap_load: Block too large for image: %" PRIu64, addr);
        return 1;
    }

    cnt = tsk_fs_read(fs, (addr + offset) * fs->block_size, (char *) hrfs->imap_buf, hrfs->fs_info.block_size); 
    if (cnt != hrfs->fs_info.block_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr2("hrfs_imap_load: Inode bitmap at %" PRIu64, addr);
        return 1;
    }

    if (PRINT_MAPS) {
        tsk_fprintf(stderr, "imap_buf:\n"); 
        hrfs_print_map(hrfs->imap_buf, hrfs->fs_info.block_size);
    }

    return 0;
}

/* 
 * hrfs_dinode_load - look up disk inode & load into hrfs_inode structure
 *
 * @param hrfs A hrfs file system information structure
 * @param dino_inum Metadata address
 * @param dino_buf The buffer to store the block in (must be size of hrfs->inode_size or larger)
 *
 * return 1 on error and 0 on success
 */
static uint8_t hrfs_dinode_load(HRFS_INFO * hrfs, TSK_INUM_T dino_inum, hrfs_inode * dino_buf){
    TSK_OFF_T addr;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & hrfs->fs_info;

    /*
     * Sanity check.
     */
    if ((dino_inum < fs->first_inum) || (dino_inum > fs->last_inum)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("hrfs_dinode_load: address: %" PRIuINUM,
            dino_inum);
        return 1;
    }

    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hrfs_dinode_load: dino_buf is NULL");
        return 1;
    }

    /*
     * Look up the inode table entry for this inode.
     */
    addr = (TSK_OFF_T) tsk_getu32(fs->endian, hrfs->fs->s_inode_table) * (TSK_OFF_T) fs->block_size  + (dino_inum - fs->first_inum) * (TSK_OFF_T) hrfs->inode_size;
    ssize_t cnt = tsk_fs_read(fs, addr, (char *) dino_buf, hrfs->inode_size);
    if (cnt != hrfs->inode_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("hrfs_dinode_load: Inode %" PRIuINUM
            " from %" PRIdOFF, dino_inum, addr);
        return 1;
    }

    if (tsk_verbose) 
        tsk_fprintf(stderr, "hrfs_dinode_load: inode=%" PRIuINUM " offset=0x%" PRIxDADDR " mode/link/size=0x%x/%d/%" PRIu64 " u/g=%d/%d mac=%" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n", 
            dino_inum, addr, tsk_getu16(fs->endian, dino_buf->i_mode), tsk_getu16(fs->endian, dino_buf->i_nlink), tsk_getu64(fs->endian, dino_buf->i_size),
            tsk_getu32(fs->endian, dino_buf->i_uid), tsk_getu32(fs->endian, dino_buf->i_gid), tsk_getu48(fs->endian, dino_buf->i_mtime)/1000, 
            tsk_getu48(fs->endian, dino_buf->i_atime)/1000, tsk_getu48(fs->endian, dino_buf->i_ctime)/1000);

    return 0;
}

/* 
 * hrfs_dinode_copy - copy cached disk inode into generic inode
 *
 * returns 1 on error and 0 on success
 */
static uint8_t hrfs_dinode_copy(HRFS_INFO * hrfs, TSK_FS_META * fs_meta, TSK_INUM_T inum, const hrfs_inode * dino_buf) {
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & hrfs->fs_info;
    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hrfs_dinode_copy: dino_buf is NULL");
        return 1;
    }
    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }
    // set the type
    switch (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_FMT) {
    case HRFS_IN_REG:
        fs_meta->type = TSK_FS_META_TYPE_REG;
        break;
    case HRFS_IN_DIR:
        fs_meta->type = TSK_FS_META_TYPE_DIR;
        break;
    case HRFS_IN_SOCK:
        fs_meta->type = TSK_FS_META_TYPE_SOCK;
        break;
    case HRFS_IN_LNK:
        fs_meta->type = TSK_FS_META_TYPE_LNK;
        break;
    case HRFS_IN_BLK:
        fs_meta->type = TSK_FS_META_TYPE_BLK;
        break;
    case HRFS_IN_CHR:
        fs_meta->type = TSK_FS_META_TYPE_CHR;
        break;
    case HRFS_IN_FIFO:
        fs_meta->type = TSK_FS_META_TYPE_FIFO;
        break;
    default:
        fs_meta->type = TSK_FS_META_TYPE_UNDEF;
        break;
    }

    // set the mode
    fs_meta->mode = 0;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_ISUID) fs_meta->mode |= TSK_FS_META_MODE_ISUID;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_ISGID) fs_meta->mode |= TSK_FS_META_MODE_ISGID;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_ISVTX) fs_meta->mode |= TSK_FS_META_MODE_ISVTX;

    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IRUSR) fs_meta->mode |= TSK_FS_META_MODE_IRUSR;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IWUSR) fs_meta->mode |= TSK_FS_META_MODE_IWUSR;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IXUSR) fs_meta->mode |= TSK_FS_META_MODE_IXUSR;

    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IRGRP) fs_meta->mode |= TSK_FS_META_MODE_IRGRP;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IWGRP) fs_meta->mode |= TSK_FS_META_MODE_IWGRP;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IXGRP) fs_meta->mode |= TSK_FS_META_MODE_IXGRP;

    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IROTH) fs_meta->mode |= TSK_FS_META_MODE_IROTH;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IWOTH) fs_meta->mode |= TSK_FS_META_MODE_IWOTH;
    if (tsk_getu16(fs->endian, dino_buf->i_mode) & HRFS_IN_IXOTH) fs_meta->mode |= TSK_FS_META_MODE_IXOTH;

    fs_meta->nlink = tsk_getu16(fs->endian, dino_buf->i_nlink);
    fs_meta->size = tsk_getu64(fs->endian, dino_buf->i_size);
    fs_meta->addr = inum;

    fs_meta->uid = tsk_getu32(fs->endian, dino_buf->i_uid);
    fs_meta->gid = tsk_getu32(fs->endian, dino_buf->i_gid);

    fs_meta->mtime = tsk_getu48(fs->endian, dino_buf->i_mtime)/1000; //HRFS uses 6 bytes, millis since epoch
    fs_meta->atime = tsk_getu48(fs->endian, dino_buf->i_atime)/1000;
    fs_meta->ctime = tsk_getu48(fs->endian, dino_buf->i_ctime)/1000;

    fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano = fs_meta->crtime = fs_meta->crtime_nano = fs_meta->seq = 0;

    if (fs_meta->link) {
        free(fs_meta->link);
        fs_meta->link = NULL;
    }

    if (fs_meta->content_len != HRFS_FILE_CONTENT_LEN) {
        if ((fs_meta = tsk_fs_meta_realloc(fs_meta, HRFS_FILE_CONTENT_LEN)) == NULL) return 1;
    }

    TSK_DADDR_T *addr_ptr;
    addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;
    for (int i = 0; i < HRFS_NDADDR + HRFS_NIADDR; i++) addr_ptr[i] = tsk_getu32(fs->endian, dino_buf->i_pointers[i]);

    /* 
     * set the link string
     * the size check prevents us from trying to allocate a huge amount of
     * memory for a bad inode value
     */
    if ((fs_meta->type == TSK_FS_META_TYPE_LNK) && (fs_meta->size < HRFS_MAXPATHLEN) && (fs_meta->size >= 0)) {
        int i = 0;
        if ((fs_meta->link = tsk_malloc((size_t) (fs_meta->size + 1))) == NULL)
            return 1;


        TSK_FS_INFO *fs = (TSK_FS_INFO *) & hrfs->fs_info;
        char *data_buf = NULL;
        char *a_ptr = fs_meta->link;
        unsigned int total_read = 0;
        TSK_DADDR_T *addr_ptr = fs_meta->content_ptr;;

        if ((data_buf = tsk_malloc(fs->block_size)) == NULL) {
            return 1;
        }

        // we only need to do the direct blocks due to the limit on path length 
        for (i = 0; i < HRFS_NDADDR && total_read < fs_meta->size; i++) {
            unsigned int cnt;
            cnt = tsk_fs_read_block(fs, addr_ptr[i], data_buf, fs->block_size); 

            if (cnt != fs->block_size) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
                tsk_error_set_errstr2
                    ("hrfs_dinode_copy: symlink destination from %" PRIuDADDR, addr_ptr[i]);
                free(data_buf);
                return 1;
            }

            int copy_len = (fs_meta->size - total_read < fs->block_size) ? (int) (fs_meta->size - total_read) : (int) (fs->block_size);
            memcpy(a_ptr, data_buf+2, copy_len); //symlink content starts with superfluous "..", skip it
            total_read += copy_len;
            a_ptr = (char *) ((uintptr_t) a_ptr + copy_len);
        }

        // terminate the string 
        *a_ptr = '\0';
        free(data_buf);
        

        // Clean up name 
        i = 0;
        while (fs_meta->link[i] != '\0') {
            if (TSK_IS_CNTRL(fs_meta->link[i])) fs_meta->link[i] = '^';
            i++;
        }
    }

    int imap_blk_num = ((inum - fs->first_inum) / fs->block_size / 8);
    tsk_take_lock(&hrfs->lock);
    if (hrfs_imap_load(hrfs, imap_blk_num)) {
        tsk_release_lock(&hrfs->lock);
        return 1;
    }

    /*
     * Ensure that inum refers to a valid bit offset in imap_buf.
     */
    if ((inum - fs->first_inum) > (imap_blk_num+1)*fs->block_size*8) {
        tsk_release_lock(&hrfs->lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("hrfs_dinode_copy: Invalid offset into imap_buf (inum %" PRIuINUM ")", inum);
        return 1;
    }


    /*
     * Apply the allocated/unallocated restriction.
     * isset() checks the opposite end of the byte that we need; the janky math below accounts for it
     */
    fs_meta->flags = (isset(hrfs->imap_buf, (((inum - fs->first_inum)%(fs->block_size*8)/8)*8 + (8-((inum - fs->first_inum)%8+1)))) ? TSK_FS_META_FLAG_UNALLOC : TSK_FS_META_FLAG_ALLOC);
    tsk_release_lock(&hrfs->lock);

    /*
     * Apply the used/unused restriction.
     */
    fs_meta->flags |= ((tsk_getu32(fs->endian, dino_buf->i_ctime) == 0xFFFFFFFF) ? TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

    return 0;
}

/* 
 * hrfs_inode_lookup - lookup inode, external interface
 *
 * Returns 1 on error and 0 on success
 *
 */
static uint8_t hrfs_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file, TSK_INUM_T inum){
    HRFS_INFO *hrfs = (HRFS_INFO *) fs;
    hrfs_inode *dino_buf = NULL;
    unsigned int size = 0;

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hrfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(HRFS_FILE_CONTENT_LEN)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    size = hrfs->inode_size > sizeof(hrfs_inode) ? hrfs->inode_size : sizeof(hrfs_inode);
    if ((dino_buf = (hrfs_inode *) tsk_malloc(size)) == NULL) {
        return 1;
    }

    if (hrfs_dinode_load(hrfs, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }
    if (hrfs_dinode_copy(hrfs, a_fs_file->meta, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }
    free(dino_buf);
    return 0;
}

/*
 * hrfs_dent_copy - copy cached directory entry into generic TSK_FS_NAME structure
 */
static uint8_t hrfs_dent_copy(HRFS_INFO * hrfs, char *hr_dent, TSK_FS_NAME * fs_name){
    TSK_FS_INFO *fs = &(hrfs->fs_info);

    hrfs_dentry *dir = (hrfs_dentry *) hr_dent;

    fs_name->meta_addr = tsk_getu32(fs->endian, dir->inode);
    // hrfs does not null terminate  I DONT KNOW WHETHER THIS IS TRUE OR NOT, NEEDS TESTING. Most every name is <254 and automatically has nulls afterwards.

    /* Copy and Null Terminate */
    strncpy(fs_name->name, dir->name, HRFS_DENT_SZ);
    //fs_name->name[dir->name_len] = '\0';
    fs_name->flags = 0;
    return 0;
}

/* hrfs_block_walk - block iterator
 *
 * flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_CONT,
 *  TSK_FS_BLOCK_FLAG_META
 *
 *  Return 1 on error and 0 on success
*/
uint8_t hrfs_block_walk(TSK_FS_INFO * a_fs, TSK_DADDR_T a_start_blk, TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags, TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr) {
    tsk_fprintf(stdout, "hrfs_block_walk: not yet implemented for HRFS\n");     
    return 1;
}

/* hrfs_inode_walk - inode iterator
 *
 * flags used: TSK_FS_META_FLAG_USED, TSK_FS_META_FLAG_UNUSED,
 *  TSK_FS_META_FLAG_ALLOC, TSK_FS_META_FLAG_UNALLOC
 *
 *  Return 1 on error and 0 on success
*/
uint8_t hrfs_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum, TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB a_action, void *a_ptr){
    char *myname = "hrfs_inode_walk";
    HRFS_INFO *hrfs = (HRFS_INFO *) fs;
    TSK_INUM_T inum;
    TSK_INUM_T end_inum_tmp;
    TSK_FS_FILE *fs_file;
    unsigned int myflags;
    hrfs_inode *dino_buf = NULL;
    unsigned int size = 0;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if(tsk_verbose) tsk_fprintf(stderr, "hrfs_inode_walk: start_inum: %" PRIuINUM ", end_inum: %"PRIuINUM", flags: 0x%X\n", start_inum, end_inum, flags);

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: start inode: %" PRIuINUM "", myname, start_inum);
        return 1;
    }

    if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: end inode: %" PRIuINUM "", myname, end_inum);
        return 1;
    }
    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        flags |= TSK_FS_META_FLAG_UNALLOC;
        flags &= ~TSK_FS_META_FLAG_ALLOC;
        flags |= TSK_FS_META_FLAG_USED;
        flags &= ~TSK_FS_META_FLAG_UNUSED;
    }else {
        // If neither of the ALOC or UNALOC flags are set, then set them both
        if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        }
        // If neither of the USED or UNUSED flags are set, then set them both
        if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
            flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
        }
    }
    
    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL) return 1;
    if ((fs_file->meta = tsk_fs_meta_alloc(HRFS_FILE_CONTENT_LEN)) == NULL) return 1;

    end_inum_tmp = end_inum - fs->first_inum;

    /*
     * Iterate.
     */
    size = hrfs->inode_size > sizeof(hrfs_inode) ? hrfs->inode_size : sizeof(hrfs_inode);
    if ((dino_buf = (hrfs_inode *) tsk_malloc(size)) == NULL) {
        return 1;
    }

    for (inum = start_inum; inum <= end_inum_tmp; inum++) {
        int retval;

        int imap_blk_num = ((inum - fs->first_inum) / fs->block_size / 8);
        tsk_take_lock(&hrfs->lock);

        if (hrfs_imap_load(hrfs, imap_blk_num)) {
            tsk_release_lock(&hrfs->lock);
            free(dino_buf);
            return 1;
        }
        
        /*
        * Ensure that inum refers to a valid bit offset in imap_buf.
        */
        if ((inum - fs->first_inum) > (imap_blk_num+1)*fs->block_size*8) {
            tsk_release_lock(&hrfs->lock);
            free(dino_buf);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
            tsk_error_set_errstr("hrfs_inode_walk: Invalid offset into imap_buf (inum %" PRIuINUM ")", inum);
            return 1;
        }

        /*
         * Apply the allocated/unallocated restriction.
         * isset() checks the opposite end of the byte that we need; the janky math below accounts for it
         */
        myflags = (isset(hrfs->imap_buf, (((inum - fs->first_inum)%(fs->block_size*8)/8)*8 + (8-((inum - fs->first_inum)%8+1)))) ? TSK_FS_META_FLAG_UNALLOC : TSK_FS_META_FLAG_ALLOC);
        tsk_release_lock(&hrfs->lock);

        if ((flags & myflags) != myflags)
            continue;

        if (hrfs_dinode_load(hrfs, inum, dino_buf)) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }

        /*
         * Apply the used/unused restriction.
         */
        myflags |= ((tsk_getu32(fs->endian, dino_buf->i_ctime) == 0xFFFFFFFF) ? TSK_FS_META_FLAG_UNUSED : TSK_FS_META_FLAG_USED);

       /*
         * Apply the orphan restriction.
         */
        if (flags & TSK_FS_META_FLAG_ORPHAN && myflags & TSK_FS_META_FLAG_USED && myflags & TSK_FS_META_FLAG_UNALLOC) myflags |= TSK_FS_META_FLAG_ORPHAN;

        if ((flags & myflags) != myflags)
            continue;

        if (hrfs_dinode_copy(hrfs, fs_file->meta, inum, dino_buf)) {
            tsk_fs_meta_close(fs_file->meta);
            free(dino_buf);
            return 1;
        }
        retval = a_action(fs_file, a_ptr);

        if (retval == TSK_WALK_STOP) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_file_close(fs_file);
    free(dino_buf);
    return 0;
}

/** \internal
 * Process an array of addresses and turn them into runs
 *
 * @param fs File system to analyze
 * @param fs_attr Data attribute to add runs to
 * @param addrs Buffer of address to process and turn into run
 * @param addr_len Number of addresses in buffer
 * @param length Length of file remaining
 *
 * @returns the number of bytes processed and -1 if an error occurred
 */
static TSK_OFF_T hrfs_make_data_run_direct(TSK_FS_INFO * fs, TSK_FS_ATTR * fs_attr, TSK_DADDR_T * addrs, size_t addr_len, TSK_OFF_T length){
    TSK_DADDR_T run_start = 0;
    TSK_DADDR_T run_len = 0;
    TSK_DADDR_T blks_processed = 0;
    size_t i;
    size_t fs_blen;             // how big is each "block" (in fragments)

    if (tsk_verbose) tsk_fprintf(stderr, "%s: block 0x%" PRIxDADDR "\n", "hrfs_make_data_run_direct", addrs[0]);
    if (addrs[0] == 0xFFFFFFFF){
        if (tsk_verbose) tsk_fprintf(stderr, "Inode direct block address is empty\n");
        return 0;
    }
    if (addr_len == 0) {
        return 0;
    }

    fs_blen = 1;    

    run_start = addrs[0];
    run_len = fs_blen;

    /* Note that we are lazy about length.  We stop only when a run is past length,
     * we do not end exactly at length -- although that should happen anyway.  
     */
    for (i = 0; i < addr_len; i++) {

        /* Make a new run if:
         * - This is the last addresss in the buffer
         * - The next address is not part of the current run
         * -- special case for sparse since they use 0 as an address
         */
        if ((i + 1 == addr_len) ||
            ((run_start + run_len != addrs[i + 1]) && (run_start != 0)) ||
            ((run_start == 0) && (addrs[i + 1] != 0))) {

            TSK_FS_ATTR_RUN *data_run;

            // make a non-resident run
            data_run = tsk_fs_attr_run_alloc();
            if (data_run == NULL)
                return -1;

            data_run->addr = run_start;
            data_run->len = run_len;

            // save the run
            tsk_fs_attr_append_run(fs, fs_attr, data_run);

            // get ready for the next run
            if (i + 1 != addr_len)
                run_start = addrs[i + 1];
            run_len = 0;

            // stop if we are past the length requested
            if (blks_processed * fs->block_size > (TSK_DADDR_T) length)
                break;
        }
        run_len += fs_blen;
        blks_processed += fs_blen;
    }

    return blks_processed * fs->block_size;
}

/** \internal
 * Read an indirect block and process the contents to make a runlist from the pointers. 
 *
 * @param fs File system to analyze
 * @param fs_attr Structure to save run data into
 * @param fs_attr_indir Structure to save addresses of indirect block pointers in
 * @param buf Buffers to read block data into (0 is block sized, 1+ are DADDR_T arrays based on FS type)
 * @param level Indirection level that this will process at (1+)
 * @param addr Address of block to read
 * @param length Length of file remaining
 *
 * @returns the number of bytes processed during call and -1 if an error occurred
 */
static TSK_OFF_T hrfs_make_data_run_indirect(TSK_FS_INFO * fs, TSK_FS_ATTR * fs_attr, TSK_FS_ATTR * fs_attr_indir, char *buf[], int level, TSK_DADDR_T addr, TSK_OFF_T length){
    size_t addr_cnt = 0;
    TSK_DADDR_T *myaddrs = (TSK_DADDR_T *) buf[level];
    TSK_OFF_T length_remain = length;
    TSK_OFF_T retval;
    size_t fs_bufsize;
    size_t fs_blen;
    TSK_FS_ATTR_RUN *data_run;

    if (tsk_verbose) tsk_fprintf(stderr, "%s: level %d block 0x%" PRIxDADDR "\n", "hrfs_make_data_run_indirect", level, addr);

    fs_blen = 1;
    fs_bufsize = fs->block_size;

    if (addr > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr("hrfs: Indirect block address too large: %"
            PRIuDADDR "", addr);
        return -1;
    }

    // make a non-resident run
    data_run = tsk_fs_attr_run_alloc();
    if (data_run == NULL) return -1;

    data_run->addr = addr;
    data_run->len = fs_blen;

    /*
     * Read a block of disk addresses.
     */
    if (addr == 0) {
        memset(buf[0], 0, fs_bufsize);
        data_run->flags = TSK_FS_ATTR_RUN_FLAG_SPARSE;
    }
    else {
        ssize_t cnt;
        // read the data into the scratch buffer
        cnt = tsk_fs_read_block(fs, addr, buf[0], fs_bufsize);
        if (cnt != (ssize_t)fs_bufsize) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("hrfs_make_data_run_indir: Block %"
                PRIuDADDR, addr);
            return -1;
        }
    }

    // save the run
    tsk_fs_attr_append_run(fs, fs_attr_indir, data_run);

    // convert the raw addresses to the correct endian ordering
    size_t n;
    uint32_t *iaddr = (uint32_t *) buf[0];
    addr_cnt = fs_bufsize / sizeof(*iaddr);
    for (n = 0; n < addr_cnt; n++) {
        myaddrs[n] = tsk_getu32(fs->endian, (uint8_t *) & iaddr[n]);
    }
    
    // pass the addresses to the next level
    if (level == 1) {
        retval =
            hrfs_make_data_run_direct(fs, fs_attr, myaddrs, addr_cnt, length_remain);
        if (retval != -1) {
            length_remain -= retval;
        }
    }
    else {
        size_t i;
        retval = 0;
        for (i = 0; i < addr_cnt && retval != -1; i++) {
            retval =
                hrfs_make_data_run_indirect(fs, fs_attr, fs_attr_indir,
                buf, level - 1, myaddrs[i], length_remain);
            if (retval == -1) {
                break;
            }
            else {
                length_remain -= retval;
            }
        }
    }

    if (retval == -1)
        return -1;
    else
        return length - length_remain;
}

/** \internal
 *
 * @returns 1 on error and 0 on success
 */
uint8_t hrfs_make_data_run(TSK_FS_FILE * fs_file) {
    TSK_OFF_T length = 0;
    TSK_OFF_T read_b = 0;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_META *fs_meta = fs_file->meta;
    TSK_FS_INFO *fs = fs_file->fs_info;

    // clean up any error messages that are lying around
    tsk_error_reset();
    if (tsk_verbose) tsk_fprintf(stderr, "hrfs_make_data_run: Processing file %" PRIuINUM "\n", fs_meta->addr);

    // see if we have already loaded the runs
    if ((fs_meta->attr != NULL)
        && (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    }
    if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }

    // not sure why this would ever happen, but...
    if (fs_meta->attr != NULL) tsk_fs_attrlist_markunused(fs_meta->attr);
    else fs_meta->attr = tsk_fs_attrlist_alloc();

    length = roundup(fs_meta->size, fs->block_size);
    if(tsk_verbose) tsk_fprintf(stderr, "File length before reading: %d.\n", length);

    if ((fs_attr = tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_NONRES)) == NULL) return 1;

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL, TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            fs_meta->size, fs_meta->size, roundup(fs_meta->size, fs->block_size), 0, 0)) return 1;

    read_b = hrfs_make_data_run_direct(fs, fs_attr, (TSK_DADDR_T *) fs_meta->content_ptr, 1, length);
    if (read_b == -1) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC)
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        return 1;
    }
    length -= read_b;
    if(tsk_verbose) tsk_fprintf(stderr, "File length remaining: %d.\n", length);

    // if there is still data left, read the indirect 
    if (length > 0) {
        if(tsk_verbose) tsk_fprintf(stderr, "Large file, getting indirect pointers.\n");
        int level;
        char *buf[4] = {NULL};
        size_t fs_bufsize0;
        size_t fs_bufsize1;
        size_t ptrsperblock;
        int numBlocks = 0;
        int numSingIndirect = 0;
        int numDblIndirect = 0;
        int numTripIndirect = 0;
        TSK_FS_ATTR *fs_attr_indir;

        fs_bufsize0 = fs->block_size;
        ptrsperblock = fs_bufsize0 / 4;

        fs_bufsize1 = sizeof(TSK_DADDR_T) * ptrsperblock;

        /*
         * Initialize a buffer for the 3 levels of indirection that are supported by
         * this inode.  Each level of indirection will have a buffer to store
         * addresses in.  buf[0] is a special scratch buffer that is used to store
         * raw data from the image (before endian conversions are applied).  It is
         * equal to one block size.  The others will store TSK_DADDR_T structures
         * and will have a size depending on the FS type. 
         */
        if ((fs_attr_indir = tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_NONRES)) == NULL) {
            return 1;
        }
        fs_bufsize0 = fs->block_size;
        ptrsperblock = fs_bufsize0 / 4;

        // determine number of indirect blocks needed for file size.
        numBlocks = (int) (((fs_meta->size + fs_bufsize0 - 1) / fs_bufsize0) - 1);
        numSingIndirect = (int) ((numBlocks + ptrsperblock - 1) / ptrsperblock);
        numDblIndirect = 0;
        numTripIndirect = 0;
        if(tsk_verbose) tsk_fprintf(stderr, "Indirect pointers: %d, %d, %d.\n", numSingIndirect, numDblIndirect, numTripIndirect);

        // double block pointer?
        if (numSingIndirect > 1) {
            numDblIndirect = (int) ((numSingIndirect - 1 + ptrsperblock - 1) / ptrsperblock);
            if (numDblIndirect > 1) {
                numTripIndirect = (int) ((numDblIndirect - 1 + ptrsperblock - 1) / ptrsperblock);
            }
        }

        // initialize the data run
        if (tsk_fs_attr_set_run(fs_file, fs_attr_indir, NULL, NULL,
                TSK_FS_ATTR_TYPE_UNIX_INDIR, TSK_FS_ATTR_ID_DEFAULT,
                fs_bufsize0 * (numSingIndirect + numDblIndirect +
                    numTripIndirect),
                fs_bufsize0 * (numSingIndirect + numDblIndirect +
                    numTripIndirect),
                fs_bufsize0 * (numSingIndirect + numDblIndirect +
                    numTripIndirect), 0, 0)) {
            return 1;
        }

        if ((buf[0] = (char *) tsk_malloc(fs_bufsize0)) == NULL) {
            return 1;
        }

        for (level = 1; length > 0 && level < 4; level++) {
            TSK_DADDR_T *addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;

            if ((buf[level] = (char *) tsk_malloc(fs_bufsize1)) == NULL) {
                int f;
                for (f = 0; f < level; f++) {
                    free(buf[f]);
                }
                return 1;
            }

            // the indirect addresses are stored in addr_ptr after the direct address 
            read_b = hrfs_make_data_run_indirect(fs, fs_attr, fs_attr_indir, buf, level, addr_ptr[level], length);
            if (read_b == -1) break;
            length -= read_b;
        }

        //Cleanup.
        for (level = 0; level < 4; ++level) {
            free(buf[level]);
        }
    }

    if (read_b == -1) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC)
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

/*
 * @param a_is_del Set to 1 if block is from a deleted directory.
 */
static TSK_RETVAL_ENUM hrfs_dent_parse_block(HRFS_INFO * hrfs, TSK_FS_DIR * a_fs_dir, uint8_t a_is_del, char *buf, int len){
    TSK_FS_INFO *fs = &(hrfs->fs_info);
    int dellen = 0;
    int idx;
    // uint16_t reclen;
    uint32_t inode;
    char *dirPtr;
    TSK_FS_NAME *fs_name;
    // int minreclen = 4;

    if ((fs_name = tsk_fs_name_alloc(HRFS_MAXNAMLEN, 0)) == NULL) return TSK_ERR;
    /* update each time by the actual length instead of the
     * recorded length so we can view the deleted entries
     */
    for (idx = 0; idx <= len - 4; idx += HRFS_DENT_SZ) {
        unsigned int namelen;
        dirPtr = &buf[idx];

        hrfs_dentry *dir = (hrfs_dentry *) dirPtr;
        inode = tsk_getu32(fs->endian, dir->inode);

        if (hrfs_dent_copy(hrfs, dirPtr, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        namelen = strlen(fs_name->name);
        //reclen = tsk_getu16(fs->endian, dir->rec_len);
        //minreclen = HRFS_DIRSIZ_lcl(namelen);

        /*
         * Check if we may have a valid directory entry.  If we don't,
         * then increment to the next possible entry and try again.
         */
        if ((inode > fs->last_inum) || (inode == 0) || (namelen == 0)) {
            if (dellen > 0)
                dellen -= 4;
            continue;
        }

        /* Before we process an entry in unallocated space, make
         * sure that it also ends in the unalloc space 

        if ((dellen) && (dellen < minreclen)) {
            minreclen = 4;
            dellen -= 4;
            continue;
        }
        // Do we have a deleted entry? 
        if ((dellen > 0) || (inode == 0) || (a_is_del)) {
            fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            if (dellen > 0)
                dellen -= minreclen;
        }
        // We have a non-deleted entry 
        else {*/
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
      //  }
        if (tsk_fs_dir_add(a_fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* If the actual length is shorter then the
         * recorded length, then the next entry(ies) have been
         * deleted.  Set dellen to the length of data that
         * has been deleted
         *
         * Because we aren't guaranteed that the next
         * entry begins right after this one, we will check to
         * see if the difference is less than a possible entry
         * before we waste time searching it
         
        if (dellen <= 0) {
            if (reclen - minreclen >= HRFS_DIRSIZ_lcl(1))
                dellen = reclen - minreclen;
            else
                minreclen = reclen;
        }*/
    }

    tsk_fs_name_free(fs_name);
    return TSK_OK;
}

/*
 * \internal
 * Process a directory and load up FS_DIR with the entries. If a pointer to
 * an already allocated FS_DIR structure is given, it will be cleared.  If no existing
 * FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return
 * value is error or corruption, then the FS_DIR structure could
 * have entries (depending on when the error occurred).
 *
 * @param a_fs File system to analyze
 * @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
 *   structure or a new structure.
 * @param a_addr Address of directory to process.
 * @returns error, corruption, ok etc.
 */
TSK_RETVAL_ENUM hrfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr){
    HRFS_INFO *hrfs = (HRFS_INFO *) a_fs;
    char *dirbuf;
    TSK_OFF_T size;
    TSK_FS_DIR *fs_dir;

    /* If we get corruption in one of the blocks, then continue processing.
     * retval_final will change when corruption is detected.  Errors are
     * returned immediately. */
    TSK_RETVAL_ENUM retval_tmp;
    TSK_RETVAL_ENUM retval_final = TSK_OK;

    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("hrfs_dir_open_meta: inode value: %" PRIuINUM "\n", a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hrfs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr, "hrfs_dir_open_meta: Processing directory %" PRIuINUM "\n", a_addr);
    }

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = a_addr; //inode 2 for HRFS
    }
    else if ((*a_fs_dir = fs_dir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) { //128 name structures
            return TSK_ERR;
    }
    //Pass NULL to allocate space for structure to store file data
    if ((fs_dir->fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_reset();
        tsk_error_errstr2_concat("- hrfs_dir_open_meta");
        return TSK_COR;
    } 
    // We only read in and process a single block at a time
    if ((dirbuf = tsk_malloc((size_t)a_fs->block_size)) == NULL) {
        return TSK_ERR;
    }
    size = roundup(fs_dir->fs_file->meta->size, a_fs->block_size);
    TSK_OFF_T offset = 0;
    while (size > 0) {
        ssize_t len = (a_fs->block_size < size) ? a_fs->block_size : size;
        ssize_t cnt = tsk_fs_file_read(fs_dir->fs_file, offset, dirbuf, len, (TSK_FS_FILE_READ_FLAG_ENUM)0);
        if (cnt != len) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_FWALK);
            tsk_error_set_errstr
            ("hrfs_dir_open_meta: Error reading directory contents: %" PRIuINUM, a_addr);
            free(dirbuf);
            return TSK_COR;
        }
        // embedded if sets a_is_del param to 1 if block is from a deleted directory.
        retval_tmp = hrfs_dent_parse_block(hrfs, fs_dir, (fs_dir->fs_file->meta->flags & 
            TSK_FS_META_FLAG_UNALLOC) ? 1 : 0, dirbuf, len);

        if (retval_tmp == TSK_ERR) {
            retval_final = TSK_ERR;
            break;
        }
        else if (retval_tmp == TSK_COR) {
            retval_final = TSK_COR;
        }

        size -= len;
        offset += len;
    }
    free(dirbuf);
    return retval_final;
}

/*
 * \internal
 * hamming_weight - count set bits of a 32-bit number 
 *   (Useful for counting set bits in bitmaps)
 *
 * @param number
 *
 * @returns 32-bit sum of set bits
 */
uint32_t hamming_weight(uint32_t i){
     i = i - ((i >> 1) & 0x55555555);
     i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
     return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

/* 
 * hrfs_bmap_load - look up a block of the block bitmap & load into cache
 *
 * Note: This routine assumes &hrfs->lock is locked by the caller.
 *
 * @param hrfs
 * @param offset Block offset in the Free Space Bitmap
 *
 * return 0 on success and 1 on error
 */
static uint8_t hrfs_bmap_load(HRFS_INFO * hrfs, int offset){
    TSK_FS_INFO *fs = (TSK_FS_INFO *) &hrfs->fs_info;
    unsigned int cnt;
    TSK_DADDR_T addr;

    // Allocate the cache buffer and exit if map is already loaded
    if (hrfs->bmap_buf == NULL) {
        if ((hrfs->bmap_buf = (uint8_t *) tsk_malloc(fs->block_size)) == NULL) {
            return 1;
        }
    }
    // Look up the block allocation bitmap.
    
    addr = tsk_getu32(fs->endian, hrfs->fs->s_free_space_bitmaps);

    if (addr > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
        tsk_error_set_errstr
            ("hrfs_bmap_load: Block too large for image: %" PRIu64, addr);
        return 1;
    }

    cnt = tsk_fs_read(fs, (addr + offset) * fs->block_size, (char *) hrfs->bmap_buf, hrfs->fs_info.block_size); 
    if (cnt != hrfs->fs_info.block_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr2("hrfs_bmap_load: Block bitmap at %" PRIu64, addr);
        return 1;
    }

    if (PRINT_MAPS) {
        tsk_fprintf(stderr, "bmap_buf:\n");
        hrfs_print_map(hrfs->bmap_buf, hrfs->fs_info.block_size);
    }
    return 0;
}

static TSK_FS_BLOCK_FLAG_ENUM hrfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr){
    HRFS_INFO *hrfs = (HRFS_INFO *) a_fs;
    int flag = 0;
    int bmap_blk_num = a_addr / a_fs->block_size / a_fs->block_size;

    tsk_take_lock(&hrfs->lock);
    if (hrfs_bmap_load(hrfs, bmap_blk_num)) {
        tsk_release_lock(&hrfs->lock);
        return 1;
    }

    // Ensure that block refers to a valid bit offset in bmap_buf.
    if (a_addr > (a_fs->block_size)*8) {
        tsk_release_lock(&hrfs->lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hrfs_block_getflags: Invalid offset into bmap_buf (addr 0x%" PRIxDADDR ")", a_addr);
        return 1;
    }

    /* Apply the allocated/unallocated restriction.
     * isset() checks the opposite end of the byte that we need; the janky math below accounts for it
     */
    flag = (isset(hrfs->bmap_buf, ((a_addr%(a_fs->block_size*8)/8)*8 + (8-(a_addr%8+1)))) ? TSK_FS_BLOCK_FLAG_UNALLOC : TSK_FS_BLOCK_FLAG_ALLOC);
    tsk_release_lock(&hrfs->lock);

    if (tsk_verbose) tsk_fprintf(stderr, "hrfs_block_getflags: block addr is: %" PRIxDADDR ", bmap_blk_num is: %d, allocation status: %s\n", a_addr, bmap_blk_num, flag == TSK_FS_BLOCK_FLAG_ALLOC ? "allocated" : "unallocated");

    return flag;
}

/************************* istat *******************************/
typedef struct {
    FILE *hFile;
    int idx;
} HRFS_PRINT_ADDR;

// Callback for istat to print the block addresses 
static TSK_WALK_RET_ENUM print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr, char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *a_ptr){
    TSK_FS_INFO *fs = fs_file->fs_info;
    HRFS_PRINT_ADDR *print = (HRFS_PRINT_ADDR *) a_ptr;
    int i, s;
    // cycle through the blocks if they exist
    for (i = 0, s = (int) size; s > 0; s -= fs->block_size, i++) {
        if (addr)
            tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr + i);
        else
            tsk_fprintf(print->hFile, "0 ");
        if (++(print->idx) == 8) {
            tsk_fprintf(print->hFile, "\n");
            print->idx = 0;
        }
    }
    return TSK_WALK_CONT;

}

/*
 * Print details on a specific file to a file handle.
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t hrfs_istat(TSK_FS_INFO * fs, TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE * hFile, TSK_INUM_T inum, TSK_DADDR_T numblock, int32_t sec_skew){
    
    HRFS_INFO *hrfs = (HRFS_INFO *) fs;
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    char ls[12];
    HRFS_PRINT_ADDR print;
    const TSK_FS_ATTR *fs_attr_indir;
    hrfs_inode *dino_buf = NULL;
    char timeBuf[128];
    unsigned int size;

    // clean up any error messages that are lying around
    tsk_error_reset();

    size = hrfs->inode_size > sizeof(hrfs_inode) ? hrfs->inode_size : sizeof(hrfs_inode);

    if ((dino_buf = (hrfs_inode *) tsk_malloc(size)) == NULL) {
        return 1;
    }

    if (hrfs_dinode_load(hrfs, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        free(dino_buf);
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "inode: %" PRIuINUM "\n", inum);
    tsk_fprintf(hFile, "%sAllocated in inode bitmap\n", (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) ? "" : "Not ");

    // Note that if this is a "virtual file", then hrfs->dino_buf may not be set.
    tsk_fprintf(hFile, "Generation Id: %" PRIu32 "\n", tsk_getu32(fs->endian, dino_buf->i_generation));

    if (fs_meta->link) tsk_fprintf(hFile, "symbolic link to: %s\n", fs_meta->link);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n", fs_meta->uid, fs_meta->gid);

    tsk_fs_meta_make_ls(fs_meta, ls, sizeof(ls));
    tsk_fprintf(hFile, "mode: %s\n", ls);

    // Print the device ids 
    if ((fs_meta->type == TSK_FS_META_TYPE_BLK) || (fs_meta->type == TSK_FS_META_TYPE_CHR)) {
        tsk_fprintf(hFile, "Device Major: %" PRIu8 "   Minor: %" PRIu8 "\n", hrfs->fs->s_ver_maj, hrfs->fs->s_ver_min);
    }
    tsk_fprintf(hFile, "size: %" PRIdOFF " bytes\n      %d blocks\n", fs_meta->size, (fs_meta->size + (fs->block_size -1))/fs->block_size); //Round up to nearest block
    tsk_fprintf(hFile, "blocks associated with file: %d\n", tsk_getu32(fs->endian, dino_buf->i_nBlocks));
    tsk_fprintf(hFile, "num of links: %d\n", fs_meta->nlink);
    tsk_fprintf(hFile, "state: marked as ");
    switch (dino_buf->i_state) {
        case 0xF8: //Special case for inodes 3-8
            tsk_fprintf(hFile, "Allocated\n");
            break;
        case 0xFE:
            tsk_fprintf(hFile, "Allocated\n");
            break;
        default:
            tsk_fprintf(hFile, "Free\n");
    }
    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Inode Times:\n");
        if (fs_meta->mtime) fs_meta->mtime -= sec_skew;
        if (fs_meta->atime) fs_meta->atime -= sec_skew;
        if (fs_meta->ctime) fs_meta->ctime -= sec_skew;
        
        tsk_fprintf(hFile, "Accessed:\t%s\n", tsk_fs_time_to_str(fs_meta->atime, timeBuf));
        tsk_fprintf(hFile, "File Modified:\t%s\n", tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
        tsk_fprintf(hFile, "Inode Modified:\t%s\n", tsk_fs_time_to_str(fs_meta->ctime, timeBuf));

        if (fs_meta->mtime) fs_meta->mtime += sec_skew;
        if (fs_meta->atime) fs_meta->atime += sec_skew;
        if (fs_meta->ctime) fs_meta->ctime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Inode Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nInode Times:\n");
    }

    tsk_fprintf(hFile, "Accessed:\t%s\n", tsk_fs_time_to_str(fs_meta->atime, timeBuf));
    tsk_fprintf(hFile, "File Modified:\t%s\n", tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
    tsk_fprintf(hFile, "Inode Modified:\t%s\n", tsk_fs_time_to_str(fs_meta->ctime, timeBuf));

    if (numblock > 0) fs_meta->size = numblock * fs->block_size;

    tsk_fprintf(hFile, "\nDirect Blocks\n");

    if (istat_flags & TSK_FS_ISTAT_RUNLIST) {
        const TSK_FS_ATTR *fs_attr_default = tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_DEFAULT, 0, 0);
        if (fs_attr_default && (fs_attr_default->flags & TSK_FS_ATTR_NONRES)) {
            if (tsk_fs_attr_print(fs_attr_default, hFile)) {
                tsk_fprintf(hFile, "\nError creating run lists\n");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
        }
    }
    else {
        print.idx = 0;
        print.hFile = hFile;

        if (tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY, print_addr_act, (void *)&print)) {
            tsk_fprintf(hFile, "\nError reading file:  ");
            tsk_error_print(hFile);
            tsk_error_reset();
        }
        else if (print.idx != 0) {
            tsk_fprintf(hFile, "\n");
        }
    }

    fs_attr_indir = tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_UNIX_INDIR, 0, 0);
    if (fs_attr_indir) {
        tsk_fprintf(hFile, "\nIndirect Blocks\n");
        if (istat_flags & TSK_FS_ISTAT_RUNLIST) {
            tsk_fs_attr_print(fs_attr_indir, hFile);
        }
        else {
            print.idx = 0;

            if (tsk_fs_attr_walk(fs_attr_indir,
                TSK_FS_FILE_WALK_FLAG_AONLY, print_addr_act,
                (void *)&print)) {
                tsk_fprintf(hFile,
                    "\nError reading indirect attribute:  ");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
            else if (print.idx != 0) {
                tsk_fprintf(hFile, "\n");
            }
        }
    }
    tsk_fs_file_close(fs_file);
    free(dino_buf);
    return 0;
}
/************************* end istat *******************************/
/*
 * Print details about the file system to a file handle.
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
uint8_t hrfs_fsstat(TSK_FS_INFO * fs, FILE * hFile){
    HRFS_INFO *hrfs = (HRFS_INFO *) fs;
    hrfs_sb *sb = hrfs->fs;
    char timeBuf[128];
    char volName[HRFS_MAXNAMLEN];
    timeBuf[0] = '\0';

    TSK_DADDR_T FSB1 = tsk_getu32(fs->endian, sb->s_free_space_bitmaps);
    TSK_DADDR_T FSB2 = tsk_getu32(fs->endian, sb->s_free_space_bitmaps + 4);
    TSK_DADDR_T FIB1 = tsk_getu32(fs->endian, sb->s_free_inode_bitmaps);
    TSK_DADDR_T FIB2 = tsk_getu32(fs->endian, sb->s_free_inode_bitmaps + 4);
    TSK_DADDR_T IT = tsk_getu32(fs->endian, sb->s_inode_table);
    TSK_DADDR_T IJ = tsk_getu32(fs->endian, sb->s_inode_journal);
    TSK_DADDR_T TM1 = tsk_getu32(fs->endian, sb->s_trans_maps);
    TSK_DADDR_T TM2 = tsk_getu32(fs->endian, sb->s_trans_maps + 4);
    TSK_DADDR_T TMR1 = tsk_getu32(fs->endian, sb->s_trans_mrs);
    TSK_DADDR_T TMR2 = tsk_getu32(fs->endian, sb->s_trans_mrs + 4);
    TSK_DADDR_T DS = tsk_getu32(fs->endian, sb->s_data_space);

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(stdout, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "File System Type: HRFS\n");
    time_t tmptime = (time_t)(tsk_getu64(fs->endian, sb->s_sb_ctime)/1000);
    tsk_fprintf(hFile, "Creation Time: %s\n", tsk_fs_time_to_str(tmptime, timeBuf));
    tsk_fprintf(hFile, "Version Number: %d.%d\n", sb->s_ver_maj, sb->s_ver_min);
    tsk_fprintf(hFile, "Volume Serial Number: 0x%04" PRIX32 "\n", tsk_getu32(fs->endian, sb->s_crc));

    // Fine Volume name from first data block
    unsigned int cnt = tsk_fs_read(fs, hrfs->first_data_block * fs->block_size, volName, HRFS_MAXNAMLEN);
    if (cnt != HRFS_MAXNAMLEN) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr2("hrfs_fsstat: volume name");
        fs->tag = 0;
        free(hrfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hrfs);
        return 1;
    }
    tsk_fprintf(hFile, "Volume Name: %s\n", volName+14); //It's the first (and unique) directory entry, don't print extraneous data from the front

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n", fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);

    if (tsk_verbose) tsk_fprintf(stderr, "Counting set bits in Free Inode Bitmap...\n");
    uint32_t inodes_available = 0;
    tsk_take_lock(&hrfs->lock);
    for (unsigned int i = 0; i < FIB2 - FIB1; i++){ //Load one block of the FIB at a time and count the set bits
        if (hrfs_imap_load(hrfs, i)) {
            tsk_release_lock(&hrfs->lock);
            return 1;
        }
        for (unsigned int x = 0; x < fs->block_size; x++) inodes_available += hamming_weight(((uint8_t *)(hrfs->imap_buf))[(x)]);
        if (tsk_verbose) tsk_fprintf(stderr, "Inode Bitmap: Block %d, sum of set bits is: %d\n", i+1, inodes_available);
    }
    tsk_release_lock(&hrfs->lock);

    tsk_fprintf(hFile, "Free Inodes: %ld\n", inodes_available); 
    tsk_fprintf(hFile, "Inode Size: %d\n", HRFS_INODE_SZ);

    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n", fs->first_block, fs->last_block);
    tsk_fprintf(hFile, "Block Size: %u\n", fs->block_size);

    if (tsk_verbose) tsk_fprintf(stderr, "Counting set bits in Free Space Bitmap...\n");
    uint32_t blocks_available = 0;
    tsk_take_lock(&hrfs->lock);
    for (unsigned int i = 0; i < FSB2 - FSB1; i++){ //Load one block of the FSB at a time and count the set bits
        if (hrfs_bmap_load(hrfs, i)) {
            tsk_release_lock(&hrfs->lock);
            return 1;
        }
        for (unsigned int x = 0; x < fs->block_size; x++) blocks_available += hamming_weight(((uint8_t *)(hrfs->bmap_buf))[(x)]);
        if (tsk_verbose) tsk_fprintf(stderr, "Block Bitmap: Block %d, sum of set bits is: %d\n", i+1, blocks_available);
    }
    tsk_release_lock(&hrfs->lock);
    tsk_fprintf(hFile, "Free Blocks: %ld\n", blocks_available);

    tsk_fprintf(hFile, "\nBLOCK GROUP INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Reserved Blocks Before Block Groups: %" PRIu32 "\n", tsk_getu32(fs->endian, sb->s_reserved_space));
    tsk_fprintf(hFile, "Number of Block Groups: %d (always 1)\n", tsk_getu32(fs->endian, sb->s_block_groups));
    tsk_fprintf(hFile, "\nGroup: 0:\n");
    tsk_fprintf(hFile, "  Inode Range: %" PRIuINUM " - %" PRIuINUM "\n", fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "  Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n", fs->first_block + tsk_getu32(fs->endian, sb->s_reserved_space), fs->last_block);
    tsk_fprintf(hFile, "  %-41s Blocks\n", "Layout:");
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Free Space Bitmap:", FSB1, FSB2 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Backup Free Space Bitmap:", FSB2, FIB1 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Free Inode Bitmap:", FIB1, FIB2 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Backup Free Inode Bitmap:", FIB2, IT - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Inode Table:", IT, IJ - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Inode Journal:", IJ, TM1 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Transaction Map:", TM1, TM2 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Backup Transaction Map:", TM2, TMR1 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Transaction Master Record:", TMR1, TMR2 - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Backup Transaction Master Record:", TMR2, DS - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Data Blocks:", DS, fs->last_block - 1);
    tsk_fprintf(hFile, "    %-33s %7" PRIuDADDR " - %" PRIuDADDR "\n", "Super Block:", fs->last_block, fs->last_block); 
    tsk_fprintf(hFile, "  Free Inodes: %d\n", inodes_available);
    tsk_fprintf(hFile, "  Free Blocks: %ld\n", blocks_available);
    tsk_fprintf(hFile, "  Stored Checksum: 0x%04" PRIX32 "\n", tsk_getu32(fs->endian, sb->s_crc));
    return 0;
}

/* 
 * hrfs_close - close an hrfs file system 
 */
static void hrfs_close(TSK_FS_INFO * fs) {
    HRFS_INFO *hrfs = (HRFS_INFO *) fs;
    fs->tag = 0;
    free(hrfs->fs);
    free(hrfs->bmap_buf);
    free(hrfs->imap_buf);
    tsk_deinit_lock(&hrfs->lock);
    tsk_fs_free(fs);
}

/*
 * Open part of a disk image as an hrfs file system.
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where hrfs file system starts
 * @param ftype Specific type of hrfs file system
 * @param test NOT USED
 *
 * @returns NULL on error or if data is not an hrfs file system
 */
TSK_FS_INFO* hrfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test){
    char *myname = "hrfs_open";
    HRFS_INFO *hrfs = NULL;
    TSK_FS_INFO *fs = NULL;
    char  read_buffer[8] = " ";
    unsigned int cnt = 0;

    // clean up any error messages that are lying around
    tsk_error_reset();
    if (tsk_verbose) {
        tsk_fprintf(stderr, "%s: img_info: %s\n", myname, img_info->images[0]);
    }
    if (TSK_FS_TYPE_ISHRFS(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS type in hrfs_open");
        tsk_fprintf(stderr, "Invalid FS type in %s", myname);
    }
	
    if ((hrfs = (HRFS_INFO *) tsk_fs_malloc(sizeof(*hrfs))) == NULL)
        return NULL;

    fs = &(hrfs->fs_info);
	
    fs->ftype = ftype;
    fs->img_info = img_info;
    fs->offset = offset;
    fs->tag = TSK_FS_INFO_TAG;
    fs->flags = 0;
	
    // Verify we are looking at an HRFS image 
    if((tsk_fs_read(fs, HRFS_MAGIC_OFF, read_buffer, 8) == -1)|| (strncmp(read_buffer, HRFS_FS_MAGIC, 8) != 0)){
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)hrfs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not an HRFS file system (magic)");
        if (tsk_verbose)
            fprintf(stderr, "%s: Bad volume descriptor: Magic number is not %s\n", myname, HRFS_FS_MAGIC);
        return NULL;
    } else if (tsk_verbose) fprintf(stderr, "%s: Found HRFS magic number.\n", myname);
	
    /* Find and read the superblock.
     * Iterate 9 through 15, multiply 2^i by number of blocks indicated at start of FS (LIT end), 
     * and check for super block magic
     */
    if ((hrfs->fs = (hrfs_sb *) tsk_malloc(sizeof(hrfs_sb))) == NULL) {
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)hrfs);
        return NULL;
    }

    uint64_t total_blocks;
    if(tsk_fs_read(fs, HRFS_TOTALBLKSOFF, read_buffer, 4) == -1){
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr2("%s: find superblock", myname);
        fs->tag = 0;
        free(hrfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hrfs);
        return NULL;
    }
    total_blocks = tsk_getu32(TSK_LIT_ENDIAN, read_buffer);
    if (tsk_verbose) fprintf(stderr, "%s: Total blocks in fs: %lld\n", myname, total_blocks);

    unsigned int potential_block_size = 512;  
    for (int i = HRFS_MIN_BLOCK_SZ; i <= HRFS_MAX_BLOCK_SZ; i++){       
        cnt = tsk_fs_read(fs, (total_blocks * potential_block_size) - potential_block_size, (char *)hrfs->fs, HRFS_ON_DISK_SB_LEN);
        if (cnt != HRFS_ON_DISK_SB_LEN) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
            tsk_error_set_errstr2("%s: superblock", myname);
            fs->tag = 0;
            free(hrfs->fs);
            tsk_fs_free((TSK_FS_INFO *)hrfs);
            return NULL;
        }
        if (tsk_verbose) fprintf(stderr, "Testing block size: %d\n", potential_block_size);
        if (strncmp(hrfs->fs->s_hrfs_id, HRFS_FS_MAGIC, 8) != 0) {
            potential_block_size*=2;
        } else { if (tsk_verbose) fprintf(stderr, "%s: Found Superblock\n", myname); break; }
    }	
	
    if (strncmp(hrfs->fs->s_hrfs_id, HRFS_FS_MAGIC, 8) != 0) {
        fs->tag = 0;
        free(hrfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hrfs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not an HRFS file system (superblock)");
        if (tsk_verbose)
            fprintf(stderr, "%s: Could not find Superblock\n", myname);
        return NULL;
    }
    // Calculate the meta data info
    fs->inum_count = tsk_getu32(fs->endian, hrfs->fs->s_inode_number); 
    fs->root_inum  = HRFS_ROOTINO;  
    fs->first_inum = HRFS_FIRSTINO; 
    fs->last_inum = fs->inum_count; 

    // Calculate the block info
    fs->block_count = tsk_getu32(fs->endian, hrfs->fs->s_total_blocks);   
    fs->first_block = 0;
    fs->last_block_act = fs->last_block = fs->block_count - 1; //This should always be the case or we'd be missing the superblock
    fs->block_size = 1 << tsk_getu16(fs->endian, hrfs->fs->s_pow_block_size);
    hrfs->first_data_block = tsk_getu32(fs->endian, hrfs->fs->s_data_space);

    // Sanity checks
    if((fs->block_size != potential_block_size) || (fs->block_size == 0) || (fs->block_size % 512)){
        fs->tag = 0;
        free(hrfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hrfs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an HRFS file system (block size)");
        if (tsk_verbose)
            fprintf(stderr, "%s: invalid block size: %d, s_pow_block_size: %d \n", myname, fs->block_size, tsk_getu16(fs->endian, hrfs->fs->s_pow_block_size));
        return NULL;
    }
    hrfs->inode_size = HRFS_INODE_SZ;

    //Initialize caches
    hrfs->imap_buf = NULL;
    hrfs->bmap_buf = NULL;    
    // Set the generic function pointers 
    fs->inode_walk = hrfs_inode_walk;
    fs->block_walk = hrfs_block_walk;
    fs->block_getflags = hrfs_block_getflags;
    fs->name_cmp = tsk_fs_unix_name_cmp;
    fs->get_default_attr_type = tsk_fs_unix_get_default_attr_type;
    fs->load_attrs = hrfs_make_data_run;
    fs->file_add_meta = hrfs_inode_lookup;
    fs->fsstat = hrfs_fsstat;
    fs->istat = hrfs_istat;
    fs->close = hrfs_close;
    fs->dir_open_meta = hrfs_dir_open_meta;
    tsk_init_lock(&hrfs->lock);
    return fs;
}