#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"
#include "main.h"


#ifdef WIN32

#define _CRT_SECURE_NO_WARNINGS
#define START_SEARCH_ADDR (0x4D8470)
#include <Windows.h>

#else

#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
typedef unsigned long DWORD;
typedef void *LPVOID;

#define START_SEARCH_ADDR (0x8168260)
//(0x8182ee0)

#endif

#define SEARCH_LENGTH (300000)
#define NUM_KEYS (256)

#include <string.h>


typedef void(*logprintf_t)(char* format, ...);

logprintf_t logprintf;
extern void *pAMXFunctions;

/*
	How to get these keys?
	First you need to send a fake seed to the player, for this you can actually use this plugin.
	Just change the szNewAuthKeys to use only one seed (put some fake text as the key)
	The player will generate a proper key from your seed, you can get it by for example sniffing on the network traffic
	received by the server.
*/
const char szNewAuthKeys[][2][43] =
{
	// seed					key
	{ "622125FA64F6617E", "E588F3E64F41498A7175B654FE93924BB7F6064D" },
	{ "32E66158218C4BCE", "41B641F4105AB6B9CEE731741DCD241F05303E11" },
	{ "48DD5FCE44D54E1E", "0C7D92ED5F0EF5E3C3F46800F1D01928212D51B2" },
	{ "1D261595176B796C", "5DAA9EFC485D5601FAAAD6A3E6890032BBE79E72" },
	{ "1D9E15AB240120FE", "6AEA2EB3EA88815D6B72681C35FB982576A15AC9" },
	{ "4E27412733742BDE", "B775489EEE5C982367DB9ADA65A107F085480F3E" },
	{ "25D3703A5A235A8E", "FFB55549FFB3C767DB07481DFDFDC6E5263815DE" },
	{ "2AAD405B47FB3A1E", "4751D5610673D0D4AA19C0F95FA98C423A0821CD" },
	{ "33CB38732EB651E", "4A650BFF41555A251CB5C3A4FD92C7923B8B66F5" },
	{ "86BA7D68BDF9118", "6864347B2BB8034B5435EE3D0FB883031DA79EFB6" },
	{ "21F2572FA472900", "8458CB79FE4498562FF7FA0863D4E2FBDFBD1838" },
	{ "6DE3C91892CA6BA", "661EF1F36A4307B6C8B157BFF1B9BA6A2F11874F" },
	{ "FD0FC21E22ED4D4", "5DD51C8F66D007F8C824EC26CDF043041674174C" },
	{ "A054D2D00D7AD72", "27DAF2DC8B1C0903EDAED13B1B9153443F176012" },
	{ "FD10E87BDD9C388", "BB1AB15D1AC02F8045562EA13B7AE5B696227BCE" },
	{ "9007A7211678FEB", "DC40B0E92006E35AAA8476450B710BA5BB74D04B" },
	{ "25855670D765DDE", "420874FD85328F1658035E96C7D0AB72C5CE820C" },
	{ "B9ECFDB71041A31", "FA91E6CFC37729391B846703C8AA41792FD480AF" },
	{ "4DE2BC6ED12D615", "9B1DA1D49D2C62B4CCE70001C5D54D2FCF26101B" },
	{ "D05963BD2A0A388", "3864DDFACEF4D124EE725E2F1FEB9A11B0B37C26" },
	{ "39C1D2F850F22D4", "641204CADB96200514BAAC4A01C75609FE1B201D" },
	{ "DD2891CE0ADEFC7", "32950191ADFCD7409DB2E6BFD67F5C621370DD26" },
	{ "60AE38FDDBDCD2B", "344D5600E874A6E872C6963423CA6FBF2745BA92" },
	{ "F495E83514B890D", "0D37B6AA5655CE94E205E8B1B6449968C91E68CE" },
	{ "9803A7FCD594671", "44961940553EE74AA6F6E980B1C6D9DABB24760E" },
	{ "1DFA5D321D70254", "7500C59EDA9FA87ECA4007EB533F4870CCC67A42" },
	{ "B070FD71D76DFC7", "6DDFC37ACCC794D34EBEE4936D711B099DA98945" },
	{ "44E7BCC82849DAB", "A4F01484C1CAB986268258F5CE52AA6AE66A3E7D" },
	{ "D8DD637EE12590D", "7FC75B32F1CEF3D0A8AE7483DDF8C239164E076A" },
	{ "7D5C02B622126E1", "341DE1D539D8B7EDEE0B2E9A83CD46D5F19D4962" },
	{ "F0C2C9F5EBFE354", "C8E34ABC11640251E893EC4678CF42DD24EA1FFA" },
	{ "94C978BC3CDBF38", "4B893411CD21E84F257DF744D1A47D22517C53ED" },
	{ "282F27E2F5C7DAB", "43E6311AC0C3CD98913C12EDA4911C32E3A88029" },
	{ "CCA6DE3146B398E", "9E99A30A7594100D41037890E19E2B7313178B09" },
	{ "50948D79FF9F6E1", "6D807CEADFBEBA4BE006E570BF439A7646A78643" },
	{ "D40B3D3F487C3D5", "F9B4BA39804580BFD7DEFF9CF2A1BD7C9C8AAD2D" },
	{ "78F1E3760968FB8", "CD22A86E6E3F12E8D163DA502783FF808B991476" },
	{ "0C7792B55245D1C", "7AA226BBC1B943AC83656F3F000C023ABD314345" },
	{ "A0DDD17C0321AFE", "4DBAC670334693946E9DF6942C609BA532EC9F59" },
	{ "6824B8CF1157220", "31C94DC99BBB3A39CAFF2991851C07FC608EE92D" },
	{ "FC9268066B43F93", "63EF15BD04C756310C952615588167403104BDBE6" },
	{ "80991EC51C2FC77", "A9131903E67397CBBF7D75402726E6EB9586BC6F" },
	{ "14FFCDFD650C9DA", "5D4E1F40BAD2881614BBC9708802DB26F19347E9" },
	{ "B8F57D4326F96CD", "D844084B53E37B9F1CF7AD04320D7A26D2117824" },
	{ "4C6CB3827ED5220", "942623506A076CC37E493012BACD54F7023C610E" },
	{ "DFDA63492FC1F04", "A5FAD5251EB375304850A8B7EFC5636028ADAF2A" },
	{ "64D0028F79ADC77", "4CFC6A71874C9A1C5DCB3691A9C9B56939514ECD" },
	{ "F847C9C7329A95B", "20AE01762397518764C1A1823A43FD56816BEDD3" },
	{ "9CCD788683766CD", "5CE32BC6432702C36E03CA389512E2643D54BE97" },
	{ "2FB427CD3C522A1", "8C3F032980C5B004A47F58617F3267974D56A1D2" },
	{ "C422DDF38D4FF04", "E27AFA08F524299D76DEFF083B3D741A1786011C" },
	{ "48998D4A462CDE8", "6A96610E853040447D67C0D610CB87E35B3D2362" },
	{ "DC9F34F9970895B", "ADB0D63855DFE0AA8EC70D599EC493BC1EC149CC" },
	{ "7FF6D33050E463E", "981EB72F0A8E69A0A39A5FAD01DBFDFED840269E" }
};


PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t)ppData[PLUGIN_DATA_LOGPRINTF];

	logprintf(" [AKModifier] SA-MP AUTH_KEY Modifier by .silent loaded!");

	/*
		Overwrite the auth keys (addresses may change in some versions)
		gap between auth_seed and auth_key: 0x20 bytes
		gap between auth_key and next auth_seed: 0x40 bytes
		gap between auth_seed and next auth_seed = 0x60 bytes

	*/

	logprintf(" [AKModifier] Scanning for address...");
	
	// Change protection of this memory area (a little bit more complicated on linux)
	int searchSize = SEARCH_LENGTH;
	#ifdef WIN32
	DWORD oldProt;
	VirtualProtect((LPVOID)START_SEARCH_ADDR, searchSize, PAGE_EXECUTE_READWRITE, &oldProt);
	#else
	size_t pageSize  = sysconf(_SC_PAGE_SIZE);
	int pageAddr = (START_SEARCH_ADDR & ~(pageSize - 1));
	
	searchSize = (START_SEARCH_ADDR - pageAddr) + (SEARCH_LENGTH);
	// Anonymous memory mapping
	LPVOID mmap_addr = mmap((LPVOID)pageAddr, searchSize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, -1, 0);
	if((int)mmap_addr == -1)
		logprintf(" [AKModifier] mmap failed (%d)", errno);
	
	if(-1 == mprotect((LPVOID)pageAddr, searchSize, PROT_READ | PROT_WRITE | PROT_EXEC))
		logprintf(" [AKModifier] mprotect failed (%d)", errno);
	#endif
	
	int addr = findSeedStartAddr(START_SEARCH_ADDR, searchSize);
	int addr_default = addr;

	if (addr == NULL)
	{
		logprintf(" [AKModifier] Couldn't find any address, aborting.");
		return true;
	}
	else
		logprintf(" [AKModifier] Start address found at 0x%x, overwriting keys...", addr);
	
	
	int arrID = 0;

	// Loop through the seeds and overwrite them
	for (int i = 0; i < NUM_KEYS; i++)
	{
		// Pad with zeros in case of longer seeds (they arent all the same length)
		for (int x = 0; x < 0x20; x++)
		{
			if ((char*)(addr + x) != '\0')
				*(char*)(addr + x) = '\0'; // pad with NULL
			else
				break; // break on NULL char
		}

		// Overwrite with our own seed (something better than strcpy should be used but fuck that)
		//strcpy((char*)(addr), "622125FA64F6617E");
		//strcpy((char*)(addr + 0x20), "E588F3E64F41498A7175B654FE93924BB7F6064D");

		strcpy((char*)(addr), szNewAuthKeys[arrID][0]);
		strcpy((char*)(addr + 0x20), szNewAuthKeys[arrID][1]);
		arrID++;
		if (arrID >= sizeof(szNewAuthKeys)/sizeof(szNewAuthKeys[0])) 
			arrID = 0;

		addr += 0x60;

		//strcpy(seed, (char*)(addr));
		//strcpy(keys, (char*)(addr)+0x20);
		//logprintf("AUTH_KEY[%d]: %s -> %s", i, seed, keys);
	}

	logprintf(" [AKModifier] Finished overwriting...");
	
	#ifdef WIN32
	VirtualProtect((LPVOID)addr_default, searchSize, oldProt, &oldProt); // restore protection
	#else
	munmap(mmap_addr, searchSize); 
	#endif

	return true;
}


#define IS_CORRECT_CHAR(a) (((char)*(DWORD*)a >= 'A' && (char)*(DWORD*)a <= 'F') || ((char)*(DWORD*)a >= '0' && (char)*(DWORD*)a <= '9'))

int CountNULLsInARow(int startAddr, int countLength)
{
	int count = 0;
	for (int i = startAddr; i < startAddr + countLength; i++)
	{
		if ((char)*(DWORD*)i == '\0')
			count++;
		else break;
	}
	return count;
}

int findSeedStartAddr(int startAddr, int searchAreaBytes)
{
	int len = 0, len2 = 0;
	int x = startAddr;
	bool b = false;
	for (startAddr; startAddr < startAddr + searchAreaBytes; startAddr++)
	{
		if((startAddr+0x20+42+30) >= x+searchAreaBytes)
		{
			return NULL;
		}
		len = 0;
		len2 = 0;
		if (IS_CORRECT_CHAR(startAddr) && IS_CORRECT_CHAR((startAddr+0x20)))
		{
			len = strlen((char*)startAddr);
			len2 = strlen((char*)(startAddr+0x20));
		}
		else
			continue;
		if ((len == 15 || len == 16) && (len2 >= 40 && len2 <= 42))
		{
			if ((CountNULLsInARow(startAddr + len, 0x20 - len) == (0x20 - len)) && (CountNULLsInARow(startAddr + 0x20 + len2, 30) == 24))
			return startAddr;
		}
		
	}
	return NULL;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	logprintf(" [AKModifier] Unloaded!");
}

/*AMX_NATIVE_INFO PluginNatives[] =
{
	{ "HelloWorld", HelloWorld },
	{ 0, 0 }
};*/

/*PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx)
{
	return amx_Register(amx, PluginNatives, -1);
}*/


/*PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx)
{
	return AMX_ERR_NONE;
}*/