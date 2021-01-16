#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/phy.h>
#include <linux/poll.h>

/*
 * TODO: May need locking implementation to avoid being susceptible to file
 * descriptor sharing concurrency issues
 */
struct mdio_debug {
	wait_queue_head_t queue;
	int value;
};

static int mdio_debug_open(struct inode *inode, struct file *file)
{
	struct mii_bus *bus = file->f_inode->i_private;
	struct mdio_debug *data;
	int err;

	data = kzalloc(sizeof *data, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	err = mutex_lock_interruptible(&bus->mdio_lock);
	if (err) {
		kfree(data);
		return err;
	}
	dev_dbg(&bus->dev, "MDIO locked for user space program.\n");

	init_waitqueue_head(&data->queue);
	data->value = -1;
	file->private_data = data;

	return 0;
}

static int mdio_debug_release(struct inode *inode, struct file *file)
{
	struct mii_bus *bus = file->f_inode->i_private;
	struct mdio_debug *data = file->private_data;

	file->private_data = NULL;

	mutex_unlock(&bus->mdio_lock);
	dev_dbg(&bus->dev, "MDIO unlocked.\n");

	kfree(data);

	return 0;
}

static ssize_t mdio_debug_write(struct file *file, const char __user *buffer, size_t size, loff_t *off)
{
	struct mii_bus *bus = file->f_inode->i_private;
	struct mdio_debug *data = file->private_data;
	char str[64] = {};
	char *s = str;
	char *token;
	int addr;
	int offset;
	int value;
	int ret;

	if (data->value != -1)
		return -EWOULDBLOCK;

	if (size > sizeof str - 1)
		return -EINVAL;

	ret = copy_from_user(str, buffer, size);
	if (ret)
		return -EFAULT;

	if (str[size-1] == '\n')
		str[size-1] = '\0';

	token = strsep(&s, ":");
	if (!token)
		return -EINVAL;
	ret = kstrtoint(token, 16, &addr);
	if (ret)
		return ret;

	token = strsep(&s, ":");
	if (!token)
		return -EINVAL;
	ret = kstrtoint(token, 16, &offset);
	if (ret)
		return ret;

	token = strsep(&s, ":");

	if (token) {
		ret = kstrtoint(token, 16, &value);
		if (ret)
			return ret;

		ret = __mdiobus_write(bus, addr, offset, value);
		if (ret)
			return ret;

		dev_dbg(&bus->dev, "write: addr=0x%.2x offset=0x%.2x value=%.4x\n",
			addr, offset, value);
	} else {
		value = __mdiobus_read(bus, addr, offset);
		if (value < 0)
			return value;

		dev_dbg(&bus->dev, "read: addr=0x%.2x offset=0x%.2x value=%.4x\n",
			addr, offset, value);

		data->value = value;
		wake_up_all(&data->queue);
	}

	return size;
}

static ssize_t mdio_debug_read(struct file *file, char __user *buffer, size_t size, loff_t *off)
{
	struct mdio_debug *data = file->private_data;
	char str[6];
	int ret;
	ssize_t rsize;

	if (data->value == -1)
		return -EWOULDBLOCK;

	rsize = snprintf(str, sizeof str, "%04x\n", data->value);
	if (rsize > size)
		return -EINVAL;

	ret = copy_to_user(buffer, str, rsize);
	if (ret)
		return -EFAULT;

	data->value = -1;
	wake_up_all(&data->queue);

	return rsize;
}

static unsigned int mdio_debug_poll(struct file *file, poll_table *wait)
{
	struct mdio_debug *data = file->private_data;

	poll_wait(file, &data->queue, wait);

	return data->value == -1 ? POLLOUT : POLLIN;
}

struct file_operations mdio_debug_fops = {
	.owner = THIS_MODULE,
	.open = mdio_debug_open,
	.release = mdio_debug_release,
	.write = mdio_debug_write,
	.read = mdio_debug_read,
	.poll = mdio_debug_poll,
};

/*
 * TODO: This implementation doesn't support module load/unload and has no
 * error checking.
 */

static struct dentry *mdio_debugfs_dentry;

void mdio_debugfs_add(struct mii_bus *bus)
{
	bus->debugfs_dentry = debugfs_create_dir(dev_name(&bus->dev), mdio_debugfs_dentry);
	debugfs_create_file("control", 0600, bus->debugfs_dentry, bus, &mdio_debug_fops);
}
EXPORT_SYMBOL_GPL(mdio_debugfs_add);

void mdio_debugfs_remove(struct mii_bus *bus)
{
	debugfs_remove(bus->debugfs_dentry);
	bus->debugfs_dentry = NULL;
}
EXPORT_SYMBOL_GPL(mdio_debugfs_remove);

int __init mdio_debugfs_init(void)
{
	mdio_debugfs_dentry = debugfs_create_dir("mdio", NULL);

	return PTR_ERR_OR_ZERO(mdio_debugfs_dentry);
}
module_init(mdio_debugfs_init);

void __exit mdio_debugfs_exit(void)
{
	debugfs_remove(mdio_debugfs_dentry);
}
module_exit(mdio_debugfs_exit);
