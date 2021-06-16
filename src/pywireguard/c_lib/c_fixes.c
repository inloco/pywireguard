#include "wireguard.h"

char *wg_list_device_names_fixed(void)
{
	char* result = wg_list_device_names();
	int index = 0;

	if(result[0] == '\0') return result;

    while(result[index] != '\0' || result[index+1]!= '\0')
    {
        if(result[index] == '\0') result[index] = '\n';
        index++;
    }
    return result;
}