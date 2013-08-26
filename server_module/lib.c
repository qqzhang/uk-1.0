

char *optarg=0;
int optind, opterr, optopt;

unsigned int
gnu_dev_major (unsigned long long int dev)
{
  return ((dev >> 8) & 0xfff) | ((unsigned int) (dev >> 32) & ~0xfff);
}

unsigned int
gnu_dev_minor (unsigned long long int dev)
{
  return (dev & 0xff) | ((unsigned int) (dev >> 12) & ~0xff);
}

unsigned long long int
gnu_dev_makedev (unsigned int major, unsigned int minor)
{
  return ((minor & 0xff) | ((major & 0xfff) << 8)
	  | (((unsigned long long int) (minor & ~0xff)) << 12)
	  | (((unsigned long long int) (major & ~0xfff)) << 32));
}
