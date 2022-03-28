
/**
 * @file 
 * @brief 
 *
 * This file provides 
 * Copyright (C) 2016 Anyka (GuangZhou) Software Technology Co., Ltd.
 * @author 
 * @date 2017-9-15
 * @version 1.0
 */

#include "rtdef.h"
#include "anyka_types.h"
//#include "partition_port.h"
#include "wifi_backup_common.h"
#include "wifi.h"


#define SDIO_PARTI     "SDIOPA"
#define WIFI_IF_PARTI  "SDIOPA"

#define AK_SUCCESS          0
#define AK_FAILED           -1

/**
 * wifi_backup_usr_data - backup/restore user data on flash 
 * @param partition - partition name
 * @param mode -  1 -write, 0 -read.
 * @param data - data pointer
 * @param len  -  data len
 * @return 0 - success -1 failed
 */
int wifi_backup_usr_data(int mode, struct wifi_info *info, int len)
{
	void *handle = NULL;
	int ret;
   
	if (info == NULL)
		return AK_FAILED;

	handle = kernel_partition_open(WIFI_IF_PARTI);
	if(handle == NULL)
	{
		printk("open %s error\n", WIFI_IF_PARTI);
        return AK_FAILED;;
	}
	else
	{        
		if (mode == MODE_WRITE)
		{
			ret = kernel_partition_write(handle, (char *)info, sizeof(struct wifi_info));
			if(ret < 0)
			{
				printk("write %s error\n", WIFI_IF_PARTI);
                ret = AK_FAILED;
			}
			else
			{
				printk("write %s ok\n", WIFI_IF_PARTI);
                ret = AK_SUCCESS;
			}
		}
		else if (mode == MODE_READ)
		{
            ret = kernel_partition_read(handle, (char *)info, sizeof(struct wifi_info));
            if(ret < 0)
            {
                printk("read %s error\n", WIFI_IF_PARTI);
                ret = AK_FAILED;
            }
            else
            {
                printk("read %s ok\n", WIFI_IF_PARTI);
                ret = AK_SUCCESS;
            }
		}

		kernel_partition_close(handle);
	}

	return ret;
}

/**
 * sdio_backup_flash_value - backup/restore SDIO data on flash 
 * @param mode -  1 -write, 0 -read.
 * @param data - data pointer
 * @param len  -  data len
 * @return 0 - success -1 failed
 */

int sdio_backup_flash_value(char mode, char *data, int len)
{
	void *handle = NULL;
	int ret;

	if (data == NULL)
		return AK_FAILED;

	handle = kernel_partition_open(SDIO_PARTI);
	if(handle == NULL)
	{
		printk("open %s error\n", SDIO_PARTI);
        ret = AK_FAILED;
	}
	else
	{
		if (mode == MODE_WRITE)
		{
			ret = kernel_partition_write(handle, data, len);
			if(ret < 0)
			{
				printk("write %s error\n", SDIO_PARTI);
                ret = AK_FAILED;
			}
			else
			{
				printk("write %s ok\n", SDIO_PARTI);
                ret = AK_SUCCESS;
			}
		}
		else if (mode == MODE_READ)
		{
			ret = kernel_partition_read(handle, data, len);
			if(ret < 0)
			{
				printk("read %s error\n", SDIO_PARTI);
                ret = AK_FAILED;
			}
			else
			{
				printk("read %s ok\n", SDIO_PARTI);
                ret = AK_SUCCESS;
			}
		}

		kernel_partition_close(handle);
	}

	return ret;
}

/*
*@brief backup sdio data
*@return 0 - backup ok, -1 others 
*/

int wifi_backup_sdio_data()
{
	int ret = -1;
	char *buffer = NULL;
	char *buffer_r = NULL;
	char *p_sdio_data = NULL;
	int sdio_data_len, sdio_data_len_r;
	
	//1.get sdio data from driver;
	if(!sdio_backup_get_data(&p_sdio_data, &sdio_data_len))
	{
		printk("get sdio data error\n");
		return -1;
	}
	printk("sdio back data len %d\n", sdio_data_len);
	buffer = malloc(sdio_data_len + 4); // sdio data + sdio data size
	if(buffer == NULL)
	{
		printk("alloc mem for sdio data error\n");
		return -1;
	}
	memcpy(buffer, &sdio_data_len, 4);//first 4 bytes store sdio_data_len
	memcpy(buffer + 4, p_sdio_data, sdio_data_len); 

	//2.read sdio data backed in flash
	ret = sdio_backup_flash_value(0, (char*)&sdio_data_len_r, 4);
	if(ret < 0 || sdio_data_len_r == 0 || sdio_data_len_r > SDIO_BACK_DATA_MAX_SIZE) 
	{
		printk("sdio_backup_flash_value read Error!\n");
	}
	else
	{
		buffer_r = malloc(sdio_data_len_r + 4); 
		if(buffer_r == NULL)
		{
			printk("alloc mem for sdio data resume error\n");
		}
		else
		{
			if(sdio_backup_flash_value(0, buffer_r, sdio_data_len_r + 4) < 0) //read data and data size
			{
				printk("Error sdio_backup_flash_value read!\n");
			}
		}
	}
	//3.compare with backed data last time, if no equal write latest value to flash
	if(sdio_data_len != sdio_data_len_r || memcmp(buffer, buffer_r, sdio_data_len) != 0)
	{
		
		if(sdio_backup_flash_value(1, buffer, sdio_data_len + 4) < 0)
		{
			printk("Error sdio backup data\n");
 		}
		else
		{
			//back sdio data success
			ret = 0;
		}
			
	}
	else
	{
		//sdio data equal to the value in flash, do not need to write again
		ret = 0;
	}
	
	free(buffer);
	free(buffer_r);
	
	return ret;
}

/*
*@brief restore sdio data
*@return 0 - restore ok, -1 others 
*/

int wifi_restore_sdio_data()
{
	int ret;
	char *buffer = NULL;
	int buffer_len;
	char *p_sdio_data;
	int sdio_data_len;
	//read data size first
	ret = sdio_backup_flash_value(0, (char*)&sdio_data_len, 4);
	if(ret < 0 || sdio_data_len == 0) 
	{
		printk("sdio_backup_flash_value read Error!\n");
		ret = -1;
	}
	else
	{
		buffer = malloc(sdio_data_len + 4); 
		if(buffer == NULL)
		{
			printk("alloc mem for sdio data resume error\n");
			return -1;
		}
		
		if(sdio_backup_flash_value(0, buffer, sdio_data_len + 4) < 0) //read data and data size
		{
			printk("Error sdio_backup_flash_value read!\n");
			free(buffer);
			return -1;
		}
		
		ret = sdio_backup_set_data(buffer + 4, sdio_data_len);
		if(ret == 1)
		{
			free(buffer);
			return 0;
		}
		else
		{
			free(buffer);
			return -1;
		}
	}
}


/**
 * backup IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param ip_info the network interface if infomation including ip gw netmask
 */

int wifi_back_ip_info(struct ip_info *wifi_ip_info)
{
	struct wifi_info wifi_info_saved;	
    memset(&wifi_info_saved, 0, sizeof(struct wifi_info));

    wifi_backup_usr_data(0, &wifi_info_saved,  sizeof(wifi_info_saved));	

    memcpy(&wifi_info_saved, wifi_ip_info, sizeof(struct ip_info));

	return wifi_backup_usr_data(1, &wifi_info_saved,  sizeof(wifi_info_saved));	
}


/**
 * resrote IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param ip_info the network interface if infomation including ip gw netmask
 */
int wifi_restore_ip_info(struct ip_info *t_ip_info)
{
	struct wifi_info wifi_info_saved;	
    memset(&wifi_info_saved, 0, sizeof(struct wifi_info));

    wifi_backup_usr_data(0, &wifi_info_saved,  sizeof(wifi_info_saved));

    if(t_ip_info != NULL)
        memcpy(t_ip_info, &wifi_info_saved.ip_info, sizeof(struct ip_info));

	return 0;	
}




