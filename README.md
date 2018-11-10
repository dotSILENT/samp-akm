# SA:MP AuthKeyModifier (Anti-RakSAMP)
This is a very simple plugin I made back in 2015 out of boredom.
It's main idea is to overwrite the default authorizaton keys (or rather the seed & key pairs).
RakSAMP has the authorization keys hardcoded, since nobody knows the exact algorithm used for generating them.
This means that it cannot send any other keys than it already knows, so this plugin makes RakSAMP useless.
The server will just reject any connection made with ANYTHING else than the original SA:MP client.
(unless someone finds a way of generating these keys)

Current number of custom auth keys: **54** out of 256 (keys are repeated to fill the rest)  
**Update**: after releasing this I actually found out that the newest RakSAMP source has the auth key generation code included, although it's not compiled in the latest release. Therefore if someone has compiled RakSAMP themselves, it makes this plugin useless.

## Installation
Simply add samp_akm.dll or samp_akm.so to your plugins folder and add them to server.cfg

This plugin was made back in times of 0.3z I think, but I've checked it and it works on both 0.3.7 r2 windows & linux server too
Although the addresses vary between every version, the plugin tries to find it automatically by scanning for a pattern in the memory

Successful output should look like this:
> Loading plugin: samp_akm  
> [AKModifier] SA-MP AUTH_KEY Modifier by .silent loaded!  
> [AKModifier] Scanning for address...  
> [AKModifier] Start address found at 0x4de3c8, overwriting keys...  
> [AKModifier] Finished overwriting...  

## Should you really use this plugin?
I don't know. I've personally never used it and only made it out of curiosity.
It could be made better, like for example load the authorization keys from a file instead of having them hardcoded.
However getting these keys isn't easy so I didn't even bother.
I release this just because I find it interesting.
