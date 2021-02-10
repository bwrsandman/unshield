#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>

#include <libunshield.h>
#include <cdio/cdio.h>
#include <cdio/iso9660.h>

bool readfile_cd(const CdIo_t *cd, lsn_t lsn, uint32_t size, uint8_t *buf)
{
  uint32_t whole_blocks = size / ISO_BLOCKSIZE;
  uint8_t extra_block[ISO_BLOCKSIZE];
  bool has_extra_block = size % ISO_BLOCKSIZE != 0;
  if (cdio_read_data_sectors(cd, buf, lsn, ISO_BLOCKSIZE, whole_blocks) != DRIVER_OP_SUCCESS)
  {
    return false;
  }
  if (has_extra_block)
  {
    if (cdio_read_data_sectors(cd, extra_block, lsn, ISO_BLOCKSIZE, 1) != DRIVER_OP_SUCCESS)
    {
      return false;
    }
    memcpy(&buf[whole_blocks * ISO_BLOCKSIZE], extra_block, size % ISO_BLOCKSIZE);
  }

  return true;
}

bool readfile_iso(const iso9660_t *iso, lsn_t lsn, uint32_t size, uint8_t *buf)
{
  uint32_t blocks = size / ISO_BLOCKSIZE + (size % ISO_BLOCKSIZE != 0);
  uint8_t *temp_buf = (uint8_t *) malloc(ISO_BLOCKSIZE * blocks);
  long int read = iso9660_iso_seek_read(iso, temp_buf, lsn, blocks);
  if (read != ISO_BLOCKSIZE * blocks)
  {
    free(temp_buf);
    return false;
  }
  memcpy(buf, temp_buf, size);
  free(temp_buf);
  return true;
}

int unshield_buffer(const char *filename, const UnshieldIoCallbacks* callbacks, void* userdata)
{
  Unshield *unshield = unshield_open2(filename, callbacks, userdata);
  if (!unshield)
  {
    fprintf(stderr, "Failed to open %s as an InstallShield Cabinet File\n", filename);
    return EXIT_FAILURE;
  }

  printf("%s contents:\n", filename);
  for (int i = 0; i < unshield_component_count(unshield); i++)
  {
    printf("%s\n", unshield_component_name(unshield, i));
  }

  return EXIT_SUCCESS;
}

typedef enum
{
    ISO_CAB_FILE_MODE_BINARY = 1 << 0,
    ISO_CAB_FILE_MODE_READ = 1 << 1,
    ISO_CAB_FILE_MODE_WRITE = 1 << 2,
    ISO_CAB_FILE_MODE_AMEND = 1 << 2,
} IsoCabFileMode;

typedef struct
{
    iso9660_stat_t *stat;
    IsoCabFileMode mode;
    long int current_offset;
} IsoCabFile;

void *isocab_fopen(iso9660_stat_t *stat, const char *modes)
{
  if (stat == NULL)
  {
    return NULL;
  }
  IsoCabFileMode mode = 0;
  if (strchr(modes, 'b') != NULL)
  {
    mode |= ISO_CAB_FILE_MODE_BINARY;
  }
  if (strchr(modes, 'r') != NULL)
  {
    mode |= ISO_CAB_FILE_MODE_READ;
  }
  if (strchr(modes, 'w') != NULL)
  {
    mode |= ISO_CAB_FILE_MODE_WRITE;
  }
  if (strchr(modes, 'a') != NULL)
  {
    mode |= ISO_CAB_FILE_MODE_AMEND;
  }
  IsoCabFile *file = (IsoCabFile *) malloc(sizeof(IsoCabFile));
  file->stat = stat;
  file->mode = mode;
  file->current_offset = 0;
  return file;
}

int isocab_fseek(void *file, long int offset, int whence, void *userdata)
{
  IsoCabFile *cab_file = file;
  printf("%s has been called\n", __FUNCTION__);
  switch (whence)
  {
    case SEEK_SET:
      cab_file->current_offset = offset;
      break;
    case SEEK_CUR:
      cab_file->current_offset += offset;
      break;
    case SEEK_END:
      cab_file->current_offset = cab_file->stat->size - offset;
      break;
    default:
      return -1;
  }
  return 0;
}

long int isocab_ftell(void *file, void *userdata)
{
  IsoCabFile *cab_file = file;
  printf("%s has been called\n", __FUNCTION__);
  return cab_file->current_offset;
}

int isocab_fclose(void *file, void *userdata)
{
  IsoCabFile *cab_file = file;
  printf("%s has been called\n", __FUNCTION__);
  iso9660_stat_free(cab_file->stat);
  free(cab_file);
  return 0;
}

typedef struct
{
    char filename[PATH_MAX];
    CdioList_t *list;
    CdioListNode_t *current_node;
    struct dirent current_dirent;
} IsoCabDir;

void *isocab_opendir(const char *name, CdioList_t *list)
{
  if (list == NULL)
  {
    return NULL;
  }
  IsoCabDir *dir = (IsoCabDir *) malloc(sizeof(IsoCabDir));
  strncpy(dir->filename, name, sizeof(dir->filename));
  dir->list = list;
  dir->current_node = _cdio_list_begin(dir->list);
  return dir;
}

int isocab_closedir(void *dir, void *userdata)
{
  IsoCabDir *cab_dir = (IsoCabDir *) dir;
  printf("%s has been called\n", __FUNCTION__);
  _cdio_list_free(cab_dir->list, true, NULL);
  free(cab_dir);
  return 0;
}

struct dirent *isocab_readdir(void *dir, void *userdata)
{
  IsoCabDir *cab_dir = (IsoCabDir *) dir;
  printf("%s has been called\n", __FUNCTION__);
  if (cab_dir->current_node == NULL)
  {
    return NULL;
  }
  memset(&cab_dir->current_dirent, 0, sizeof(cab_dir->current_dirent));
  const iso9660_stat_t *stat = _cdio_list_node_data(cab_dir->current_node);
  cab_dir->current_dirent.d_ino = stat->lsn;
  cab_dir->current_dirent.d_off = stat->lsn;
  cab_dir->current_dirent.d_reclen = stat->size;
  switch (stat->type)
  {
    case _STAT_FILE:
      cab_dir->current_dirent.d_type = DT_REG;
      break;
    case _STAT_DIR:
      cab_dir->current_dirent.d_type = DT_DIR;
      break;
    default:
      cab_dir->current_dirent.d_type = DT_UNKNOWN;
      break;
  }
  char filename[PATH_MAX];
  iso9660_name_translate(stat->filename, filename);
  strncpy(cab_dir->current_dirent.d_name, filename, sizeof(cab_dir->current_dirent.d_name));

  cab_dir->current_node = _cdio_list_node_next(cab_dir->current_node);

  return &cab_dir->current_dirent;
}

typedef struct
{
    CdIo_t *cd;
    const uint8_t *buf;
    uint32_t size;
} IsoCabIoCallbacksCDUserData_t;

void *isocab_cd_fopen(const char *filename, const char *modes, void *userdata)
{
  IsoCabIoCallbacksCDUserData_t *userdata_cd = (IsoCabIoCallbacksCDUserData_t *) userdata;
  printf("%s has been called\n", __FUNCTION__);
  iso9660_stat_t *stat = iso9660_fs_stat(userdata_cd->cd, filename);
  return isocab_fopen(stat, modes);
}

size_t isocab_cd_fread(void *ptr, size_t size, size_t n, void *file, void *userdata)
{
  IsoCabIoCallbacksCDUserData_t *userdata_cd = (IsoCabIoCallbacksCDUserData_t *) userdata;
  IsoCabFile *cab_file = file;
  printf("%s has been called\n", __FUNCTION__);
  size_t read = 0;
  if (readfile_cd(userdata_cd->cd, cab_file->stat->lsn, n * size, ptr))
  {
    read += size * n;
    cab_file->current_offset += size * n;
  }
  return read;
}

size_t isocab_cd_fwrite(const void *ptr, size_t size, size_t n, void *file, void *userdata)
{
  IsoCabIoCallbacksCDUserData_t *userdata_cd = (IsoCabIoCallbacksCDUserData_t *) userdata;
  printf("%s has been called\n", __FUNCTION__);
  assert(false);  // TODO: Not implemented
  return 0;
}

void *isocab_cd_opendir(const char *name, void *userdata)
{
  IsoCabIoCallbacksCDUserData_t *userdata_cd = (IsoCabIoCallbacksCDUserData_t *) userdata;
  printf("%s has been called\n", __FUNCTION__);
  // TODO don't fix here
  if (strlen(name) == 0)
  {
    name = "/";
  }
  CdioList_t *list = iso9660_fs_readdir(userdata_cd->cd, name);
  return isocab_opendir(name, list);
}

static UnshieldIoCallbacks isocabIoCDCallbacks = {
        .fopen = isocab_cd_fopen,
        .fseek = isocab_fseek,
        .ftell = isocab_ftell,
        .fread = isocab_cd_fread,
        .fwrite = isocab_cd_fwrite,
        .fclose = isocab_fclose,
        .opendir = isocab_cd_opendir,
        .closedir = isocab_closedir,
        .readdir = isocab_readdir,
};

int unshield_buffer_cd(CdIo_t *cd, const char *filename, const uint8_t *buf, uint32_t size)
{
  IsoCabIoCallbacksCDUserData_t userdata = {
          .cd = cd,
          .buf = buf,
          .size = size,
  };
  return unshield_buffer(filename, &isocabIoCDCallbacks, &userdata);
}

typedef struct
{
    iso9660_t *cd;
    const uint8_t *buf;
    uint32_t size;
} IsoCabIoCallbacksISOUserData_t;

void *isocab_iso_fopen(const char *filename, const char *modes, void *userdata)
{
  IsoCabIoCallbacksISOUserData_t *userdata_iso = (IsoCabIoCallbacksISOUserData_t *) userdata;
  printf("%s has been called\n", __FUNCTION__);
  iso9660_stat_t *stat = iso9660_ifs_stat(userdata_iso->cd, filename);
  return isocab_fopen(stat, modes);
}

size_t isocab_iso_fread(void *ptr, size_t size, size_t n, void *file, void *userdata)
{
  IsoCabIoCallbacksISOUserData_t *userdata_iso = (IsoCabIoCallbacksISOUserData_t *) userdata;
  IsoCabFile *cab_file = file;
  printf("%s has been called\n", __FUNCTION__);
  size_t read = 0;
  if (readfile_iso(userdata_iso->cd, cab_file->stat->lsn, n * size, ptr))
  {
    read += size * n;
    cab_file->current_offset += size * n;
  }
  return read;
}

size_t isocab_iso_fwrite(const void *ptr, size_t size, size_t n, void *file, void *userdata)
{
  IsoCabIoCallbacksCDUserData_t *userdata_iso = (IsoCabIoCallbacksCDUserData_t *) userdata;
  printf("%s has been called\n", __FUNCTION__);
  assert(false);  // TODO: Not implemented
  return 0;
}

void *isocab_iso_opendir(const char *name, void *userdata)
{
  IsoCabIoCallbacksISOUserData_t *userdata_iso = (IsoCabIoCallbacksISOUserData_t *) userdata;
  printf("%s has been called\n", __FUNCTION__);
  // TODO don't fix here
  if (strlen(name) == 0)
  {
    name = "/";
  }
  CdioList_t *list = iso9660_ifs_readdir(userdata_iso->cd, name);
  return isocab_opendir(name, list);
}

static UnshieldIoCallbacks isocabIoISOCallbacks = {
        .fopen = isocab_iso_fopen,
        .fseek = isocab_fseek,
        .ftell = isocab_ftell,
        .fread = isocab_iso_fread,
        .fwrite = isocab_iso_fwrite,
        .fclose = isocab_fclose,
        .opendir = isocab_iso_opendir,
        .closedir = isocab_closedir,
        .readdir = isocab_readdir,
};

int unshield_buffer_iso(iso9660_t *cd, const char *filename, const uint8_t *buf, uint32_t size)
{
  IsoCabIoCallbacksISOUserData_t userdata = {
          .cd = cd,
          .buf = buf,
          .size = size,
  };
  Unshield *unshield = unshield_open2(filename, &isocabIoISOCallbacks, &userdata);
  if (!unshield)
  {
    fprintf(stderr, "Failed to open %s as an InstallShield Cabinet File\n", filename);
    return EXIT_FAILURE;
  }

  printf("%s contents:\n", filename);
  for (int i = 0; i < unshield_component_count(unshield); i++)
  {
    printf("%s\n", unshield_component_name(unshield, i));
  }

  return EXIT_SUCCESS;
}

int cdinfo_cd(CdIo_t *cd, const char *cab_filename)
{
  iso9660_pvd_t pvd;
  if (iso9660_fs_read_pvd(cd, &pvd))
  {
    printf("Application: %s\n", pvd.application_id);
    printf("Preparer: %s\n", pvd.preparer_id);
    printf("Publisher: %s\n", pvd.publisher_id);
    printf("System: %s\n", pvd.system_id);
    printf("Volume: %s\n", pvd.volume_id);
    printf("Volume Set: %s\n", pvd.volume_set_id);
  }

  CdioList_t *list = iso9660_fs_readdir(cd, "/");

  if (list)
  {
    /* Iterate over the list of files.  */
    CdioListNode_t *node;
    _CDIO_LIST_FOREACH(node, list)
    {
      char filename[4096];
      iso9660_stat_t *stat = _cdio_list_node_data(node);
      iso9660_name_translate(stat->filename, filename);
      printf("%s [LSN %6d] %8u %s%s\n",
             2 == stat->type ? "d" : "-",
             stat->lsn, stat->size, "/", filename);
    }
    _cdio_list_free(list, true, NULL);
  }

  {
    iso9660_stat_t *stat = iso9660_fs_stat(cd, cab_filename);
    if (stat == NULL)
    {
      fprintf(stderr, "Could not find %stat\n", cab_filename);
      return EXIT_FAILURE;
    }
    uint8_t *file_buf = malloc(stat->size);
    if (!readfile_cd(cd, stat->lsn, stat->size, file_buf))
    {
      free(file_buf);
      return EXIT_FAILURE;
    }
    printf("%s (%u bytes)\n", cab_filename, stat->size);
    int result = unshield_buffer_cd(cd, cab_filename, file_buf, stat->size);
    free(file_buf);
    if (result != EXIT_SUCCESS)
    {
      return result;
    }
  }

  return EXIT_SUCCESS;
}

int cdinfo_iso(iso9660_t *cd, const char *cab_filename)
{
  iso9660_pvd_t pvd;
  if (iso9660_ifs_read_pvd(cd, &pvd))
  {
    printf("Application: %s\n", pvd.application_id);
    printf("Preparer: %s\n", pvd.preparer_id);
    printf("Publisher: %s\n", pvd.publisher_id);
    printf("System: %s\n", pvd.system_id);
    printf("Volume: %s\n", pvd.volume_id);
    printf("Volume Set: %s\n", pvd.volume_set_id);
  }

  CdioList_t *list = iso9660_ifs_readdir(cd, "/");

  if (list)
  {
    /* Iterate over the list of files.  */
    CdioListNode_t *node;
    _CDIO_LIST_FOREACH(node, list)
    {
      char filename[4096];
      iso9660_stat_t *stat = _cdio_list_node_data(node);
      iso9660_name_translate(stat->filename, filename);
      printf("%s [LSN %6d] %8u %s%s\n",
             2 == stat->type ? "d" : "-",
             stat->lsn, stat->size, "/", filename);
    }
    _cdio_list_free(list, true, NULL);
  }

  {
    iso9660_stat_t *stat = iso9660_ifs_stat(cd, cab_filename);
    if (stat == NULL)
    {
      fprintf(stderr, "Could not find %stat\n", cab_filename);
      return EXIT_FAILURE;
    }
    uint8_t *file_buf = malloc(stat->size);
    if (!readfile_iso(cd, stat->lsn, stat->size, file_buf))
    {
      free(file_buf);
      return EXIT_FAILURE;
    }
    printf("%s (%u bytes)\n", cab_filename, stat->size);
    int result = unshield_buffer_iso(cd, cab_filename, file_buf, stat->size);
    free(file_buf);
    if (result != EXIT_SUCCESS)
    {
      return result;
    }
  }

  return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    fprintf(stderr, "Missing path to CD-ROM device or pseudo CD-ROM\n");
    return EXIT_FAILURE;
  }

  if (argc < 3)
  {
    fprintf(stderr, "Missing path to cab file in CD-ROM device or pseudo CD-ROM\n");
    return EXIT_FAILURE;
  }

  {
    CdIo_t *device = cdio_open(argv[1], DRIVER_UNKNOWN);
    if (device != NULL)
    {
      printf("CDIO detected the driver: %s\n", cdio_get_driver_name(device));
      return cdinfo_cd(device, argv[2]);
    }
  }

  {
    iso9660_t *iso = iso9660_open_ext(argv[1], ISO_EXTENSION_NONE);
    if (iso != NULL)
    {
      printf("ISO 9660 detected the driver\n");
      return cdinfo_iso(iso, argv[2]);
    }
  }

  fprintf(stderr, "Could not open CD-ROM device or pseudo CD-ROM\n");
  return EXIT_FAILURE;
}
