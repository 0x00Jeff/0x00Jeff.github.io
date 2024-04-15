---
title: Dynamically Extracting The Encryption Key From A Simple Ransomware
date: 2022-02-18 22:19:00 +0100
categories: [Windows]
tags: [OS internals, WIndows Loader, Hooking, Reverse engineering, Dll hacking]
render_with_liquid: false
---

recently I've played ransomware101 room in [secdojo website](https://www.sec-dojo.com/) where I was given a windows box that has a flag ecrypted by a ransomware, and I had to figure out the decryption key to recover it, the ransomware key generation function worked like the following:

  - get the computer name
  - get the mac address
  - concatenate them
  - md5

it generated the same key everytime for the same computer, so I wanted to see if I could use the built-in key generation function to dynamically extract the key from the ransomware

I had came up with 2 ways to do it, I had spent few days trying to get the first one to work, when I randomly stumbled upon another way, and was able to get it to work under 2 hours, I'm gonna touch on the second one first as it seems easier and more practical

first we need to make one piece of information known, my goal is to call the function in the ransomware that is responsible for generating the encryption keys. to do that I need to load the dll into my process, however the second I load it, its entry point will be called making it do its thing, which is encrypting my files

so basically what I was trying to figure out is a way to load the dll without its entry point/DllMain being called, I also wanted to make take this an opportunity to learn something new, so no manual mapping (not that it wouldn't be a valid solution), and absolutely no patching on disk

## second method : Dll Load notifications

according to the [docs](https://docs.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification), `LdrRegisterDllNotification` lets you register a Dll callback that gets executed before the dynamic linking occurs, that is our callback function will be called everytime a dll is loaded/unloaded, before the Dll entry is called, which doesn't happen until the callbacks function returns, this is perfect for this situations as it lets us do whatever we want the dll before it's entry gets executed which is just what I need

now the plan is :
  - register a dll callback
  - load the ransomeware dll
  - when the the control is handed to the callback function, place a `ret` at the beginning of DllMain, this will make it return as soon as it's called, while at the same time letting the entry point gets executed which causes the dll to correctly initialize
  - call the function responsible for generating the encryption keys

### registering a dll callback

```c
#define DLL_NAME		"r101.dll"
#define WIDE_DLL_NAME		L""DLL_NAME
...

    // Get a handle to ntdll
    HANDLE HNtdll = GetModuleHandleA("ntdll.dll");
    if(!HNtdll){
        fprintf(stderr, "couldn't Get a handle to ntdll.dll :(\n");
        return -1;
    }

    // get the address of LdrRegisterDllNotification
    LdrRegisterDllNotification f = (LdrRegisterDllNotification)GetProcAddress(HNtdll, "LdrRegisterDllNotification");
    if(!f){
        fprintf(stderr, "LdrRegisterDllNotification not found :(\n");
        return -1;
    }

    // register a dll callback
    PVOID cookie = NULL;
    if(f(0, LdrDllNotification, (PVOID)WIDE_DLL_NAME, &cookie) != STATUS_SUCCESS){
    	fprintf(stderr, "LdrRegisterDllNotification failed with error code = %ld\n", GetLastError());
    	return -1;
    }
```

first we get a handle to `Ntdll.dll`, check for the presence of `LdrRegisterDllNotification` in the said dll and resolve its address, then register a notification callback which will call the function `LdrDllNotification` that we're going to cover in a bit, the callback function gets a pointer to the dll name we're trying to patch as an argument

## load the ransomeware dll

then we simply load the dll using `LoadLibraryA` this will cause our callback function to be called with generic info about the loaded dll, plus a pointer to the dll name we pass to it

```c
  HMODULE Htry = LoadLibraryA(DLL_NAME);
  if(!Htry){
    fprintf(stderr, "couldn't find %s :(\n", DLL_NAME);
    return -1;
  }
```

## patching DllMain

the signature of our callback should take the following form

```c
VOID CALLBACK LdrDllNotification(
  _In_     ULONG                       NotificationReason,
  _In_     PCLDR_DLL_NOTIFICATION_DATA NotificationData,
  _In_opt_ PVOID                       Context
);
```

where upon loading a dll, `NotificationReason` has the value `LDR_DLL_NOTIFICATION_REASON_LOADED`,  `NotificationData` is an `_LDR_DLL_LOADED_NOTIFICATION_DATA` struct containing the following info

```c
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
}
```

so each time the callback function is called, it gets the Dllname, DllPath, the address where the dll is loaded, its size, and a `Context` pointer, which is an argument we control, in this case it's the name of the dll we want to patch

now we just calculate the address of DllMain with the next steps so I can patch it
  - open the dll is disassembler of your choosing (mine is ida)
  - rebase the program to 0
  - go to dllMain and check its offset

  we end up with the offset value `0x2600`

  ![DllMain_offset](https://user-images.githubusercontent.com/71389295/153338189-45dc4b66-95d0-4ecb-b654-aecd339189c4.png)

this means that if you know where the dll is loaded in memory, if you added `0x2600` to that address, you get the address of `DllMain`. now as mentioned before, our callbcks function gets this peace of information every time a dll is loaded, here's what the callback function looks like

```c
#define DLL_MAIN_OFFSET 0x2600
...
VOID CALLBACK LdrDllNotification(
  _In_     ULONG                       NotificationReason,
  _In_     PCLDR_DLL_NOTIFICATION_DATA NotificationData,
  _In_opt_ PVOID                       Context
){

    PBYTE ptr;
    DWORD OldProtection;

    wchar_t *target_dll = (wchar_t *)Context;

    if(NotificationReason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;

    if(wcscmp(target_dll, NotificationData -> Loaded.BaseDllName -> Buffer))
        return;

    ptr = NotificationData -> Loaded.DllBase;
    if(!VirtualProtect(ptr + DLL_MAIN_OFFSET, 1, PAGE_EXECUTE_READWRITE, &OldProtection)){
        fprintf(stderr, "VirtualProtect failed with code = %ld\n", GetLastError());
        return;
    }

    // make DllMain return as soon as it's called
    // so our files don't get encrypted
    *(ptr + DLL_MAIN_OFFSET) = 0xc3;
}
```

this function checks for the loaded dlls, compare their names with the dll we want to patch, makes the first byte at the DllMain writable so we can edit it, then writes a `0xc3` into it, this will make DllMain returs as soon as it's called

## call the key generation function
the function generating the keys is the second function that gets called inside `StartRansomware()`. in the same way we did before, we get the offset `0x20e0`

![key_gen_function](https://user-images.githubusercontent.com/71389295/153339810-44ca09b1-0736-446e-a994-f2ca226179bc.png)

the function takes no arguments, and returns a `char` pointer of to the encryption key. now all we have to do is declare a function pointer of the said type, make it point to our function, then call it and print the key

now if you remember the code that we used before to gets our callback function called

```c
  HMODULE Htry = LoadLibraryA(DLL_NAME);
  if(!Htry){
    fprintf(stderr, "couldn't find %s :(\n", DLL_NAME);
    return -1;
  }
```

this puts the dll address in `Htry`, knowing the offset to the function we can do this

```c
#define KEY_GENERATION_OFFSET 0x20e0

...
  key_gen my_key_gen = (key_gen)((PBYTE)dll + KEY_GENERATION_OFFSET);
  printf("key = %s\n", my_key_gen());
```

and this is the result we get

![key_extraction](https://user-images.githubusercontent.com/71389295/153423257-6d97604d-54bd-4609-858f-8aa1a516d828.png)

## first method : patching ntdll

my initial thought of the process that I would have to go through was the following :

  1. load the dll into my own process
  2. call the key generation functions
  3. profit

but this small list went a bit wrong as you'll read here

# loading the dll

this bit was the most time consuming to figure out. as the next parts would explain in the details the approaches that I took, and how did they miserably fail

## first idea : LoadLibraryA

I had a dll I can practice on, all it did was displaying a message using `MessageBoxW`. the problem is, as soon as I loaded it using `LoadLibraryA`, a little message box popped, reminding me of the fact that the said function not only loads dlls into the process address space but also calls their entry point which eventually calls its `DllMain` causing the dll to do its thing, which in this case is, encrypting our files so this route wouldn't work

## second idea : LoadLibraryExA

this function is basically `LoadLibraryA` with additional loading options, one of those options is `DONT_RESOLVE_DLL_REFERENCES` which according to [msdn docs](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) does the following

    If this value is used, and the executable module is a DLL, the system does not call DllMain for process and thread initialization and termination. Also, the system does not load additional executable modules that are referenced by the specified module.

I thought to my self "a function that doesn't call `DllMain`, great!". but I later found out that this wound't work for 2 reasons

the first one according to the msdn docs is that this flag is used when one wants to **access only data or resources in the DLL**, this means that it won't be executable, this however was a problem I could deal with by changing the memory protections

the other one which as the flag name `DONT_RESOLVE_DLL_REFERENCES` suggest is ... yep, the function doesn't resolve the references, including the function imports, but what does this mean ?

in a normal scenario, your dll calls a function, `MessageBoxW` in my case. the OS loader makes sure the function exists in memory by loading the dll that contains it, it also ensures that your dll is calling the right address at which the said function resides. in other words, the OS loader got your back

but when loading a dll with `DONT_RESOLVE_DLL_REFERENCES`, the function your dll tries to call doesn't exist in memory, and by the time your dll tries to call the address where it's supposed to be, it actually calls into a place filled with zeroes causing the program to crash (I had to learn this the hard way)

## third idea : a deeper look into LoadLibraryA

by this time, I know using `LoadLibraryExA` with any special flags is wound't work, but what about `LoadLibraryA` ? (btw `LoadLibraryA` is just a wrapper arround `LoadlibraryExA`, calling `LoadLibraryA(libname)` is the equivalent of calling `LoadLibraryExA(libname, 0)`, the second argument being 0 means no speciall loading flags. the deal breaker is not really which function is being called, but the flags argument that ends up in `LoadLibraryExA`)

`LoadLibraryA` does everything I want to do, it loads a dll with the right memory protections and everything, it only does one thing that I don't need, so why not try to get ride of it ? this was the time to reverse `LoadLibraryA` to figure out at which point it calls the dll's entry point so I can patch it away

after some stepping over and out of functions, I've found the one responsible for calling the Dll EntryPoint and how it's reached from `LoadLibrary`


```
LoadLibrary()	-> kernel32.LoadLibraryEx
		-> kernelbase.LoadLibraryExA
		-> kernelbase.LoadLibraryExW
		-> ntdll.LdrLoadDll
		-> ntdll.LdrpLoadDll (not exported)
		-> ntdll.LdrpPrepareModuleForExecution (not exported)
		-> ntdll.LdrpInitializeGraph (not exported)
		-> ntdll.LdrpInitializeNode (not exported)
		-> ntdll.LdrpCallTlsInitialiazers (not exported)
		-> ntdll.LdrpCallInitRoutine (not exported)
		-> call rsi (rsi has a function pointer pointing at the dll entry point)
```

(the function names can change between windows versions i.e I found that windows 10 has `LdrpLoadDllInternal` instead of `LdrpLoadDll`)

`ntdll.LdrpCallInitRoutine` was the function responsible for calling the Dll entry point by executing the following instructions

```asm
00007FF88EA6DCEA            | 4D:8BC6          | mov r8,r14
00007FF88EA6DCED            | 8BD3             | mov edx,ebx
00007FF88EA6DCEF            | 48:8BCF          | mov rcx,rdi
00007FF88EA6DCF2            | FFD6             | call rsi
```

where `rsi` is pointing to the DLl EntryPoint

now if we `nop`ed out those instructions the dll entry won't be called, but that would happen for *every* dll that is being loaded which would cause the program to crash when trying to call functions from newly loaded dlls


so I tried hooking `ntdll.LdrLoadDll` since it's the last exported function that gets the dll name. so my method was

	- intercept the dlls being loaded
	- if the dll name matches out target dll patch `ntdll.LdrpCallInitRoutine` so it doesn't call the entry point
	- unpatch `ntdll.LdrpCallInitRoutine` so every other dll loads just fine

also the way I found where `ntdll.LdrpCallInitRoutine` is in memory for now, since it's not exported, was the following, in my ntdll at least, the said function existed exactly 274 bytes after `RtlActivateActivationContextUnsafeFast` (a random function located right before the one I'm searching for), so I used `GetProcAddress` on the said function then calculated the address from there

so basically something like this

```c
#define CALL_RSI_OFFSET 274
// the address of the call instruction that invokes the dll entry point in ntdll.LdrpCallInitRoutine 
PBYTE call_rsi;
PVOID MyLdrLoadDll;

int main(void){

	// Get a handle to ntdll
	HANDLE HNtdll = GetModuleHandleA("ntdll.dll");
	if(!HNtdll){
		fprintf(stderr, "couldn't find ntdll.dll :(");
		return -1;
	}

	// get the address of the `call rsi` responsible for calling the dll entry point
	PVOID base = (PVOID)GetProcAddress(HNtdll, "RtlActivateActivationContextUnsafeFast");
	call_rsi = (PBYTE)base + CALL_RSI_OFFSET;

	// get the address of LdrLoadDll
	MyLdrLoadDll = (_LdrLoadDll)GetProcAddress(HNtdll, "LdrLoadDll");
	if(!MyLdrLoadDll){
		fprintf(stderr, "couldn't find LdrLoadDll :(");
		return -1;
	}

	// hook LdrLoadDll
	hook((PVOID)MyLdrLoadDll, (PVOID)FakeLdrLoadDll);
```

and here's my `FakeLdrLoadDll` function

```c
NTSTATUS WINAPI FakeLdrLoadDll( PWSTR IN SearchPath,
		PULONG IN LoadFlags,
		PUNICODE_STRING DllName,
		HMODULE *BaseAddress){

	char *original_bytes = malloc(call_rsi_len * sizeof(char));
	if(!original_bytes){
		fprintf(stderr, "calloc failed with error : %ld\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	BOOL IsTargetDll = !!wcscmp(WIDE_DLL_NAME, DllName -> Buffer);

	if(!IsTargetDll)
		patch(call_rsi, original_bytes);

	// un-hook LdrLoadDll
	unhook(MyLdrLoadDll);

	// invoke the unhooked LdrLoadDll
	if(MyLdrLoadDll(SearchPath, LoadFlags, DllName, BaseAddress))
		fprintf(stderr, "I couldn't load %ls :(\n", DllName -> Buffer);

	// re-hook
	hook((PVOID)MyLdrLoadDll, FakeLdrLoadDll);

	// unpatch
	if(!IsTargetDll)
		unpatch(call_rsi, original_bytes);

	free(original_bytes);

	// return True meaning the dll was sucessfully loaded
	return TRUE;
}
```

`patch` just put `nop`s out the `call rsi` while unpatch puts the original bytes back

this ensures that every dll except our target one will have its entry point called causing it to be correctly initialized

then I simply loaded the dll

```c
	dll = LoadLibraryA(DLL_NAME);
	if(!dll){
		fprintf(stderr, "couldn't load %s, error code = %ld\n", DLL_NAME, GetLastError());
		return -1;
	}
```

now that the dll resides in memory, I need to

  - put a 0xc3 at the first byte of DllMain so calling the dll entry point won't encrypt my files
  - manually call the dll entry point so the Dll gets initialized
  - call the key generation function to get the key

### patching DllMain

``` c
#define DLL_TO_DLLMAIN	0x2600
...
	DllMain MyDllMain = (DllMain)((PBYTE)dll + DLL_TO_DLLMAIN);
	PatchDllMain(MyDllMain);
...

void PatchDllMain(PVOID addr){
	DWORD whatever;

	if(!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &whatever)){
		fprintf(stderr, "VirtualProtect failed with code = %ld\n", GetLastError());
		return;
	}

	// TODO : make the source match this line (deleted ptr var)
	*(PBYTE)addr =  0xc3;
}
```

### calling the dll EntryPoint

```c
#define DLL_TO_ENTRY	0x1C6AC
...

	DllEntry EntryPoint = (DllEntry)((PBYTE)dll + DLL_TO_ENTRY);
	EntryPoint(dll, DLL_PROCESS_ATTACH, NULL);
```

## extracting the encryption key

```c
	key_gen my_key_gen = (key_gen)((PBYTE)dll + KEY_GENERATION_OFFSET);
	printf("key = %s\n", my_key_gen());
```

### result

![where_key](https://user-images.githubusercontent.com/71389295/153695749-3ddfef3c-6559-47d7-95e3-80ac6a99ceee.png)

ayo ???? why am I getting an access violation instead of the encryption key

this part threw me off a bit, every step was done just like it's supposed to be, and I couldn't make sense of what the problem was

I tried on a different dll that all it did was pop a message using `MessageBoxW` and was faced with the same result

what made it even confusing is the fact that the dll code was being called, and the access violation was happening inside a random internal function in `ntdll` (`RtlAllocateHeap` for the ransomware, and some other `Nt*` function that `MessageBoxW` calls into in the other one)

the solution was found by accident when I was trying different stuff to debug it. and for the dll that uses `MessageBox` was loading `user32.dll` before loading the test dll, this made no sense to me because

	A. that dll was already in memory before I loaded my test dll
	B. loading the test dll should cause any dll dependency to load as well

so I went to the ransomware dll, figured out what function was calling `RtlAllocateHeap`, it was `GetAdaptersInfo`, looked up what dll it's located in (Iphlpapi.dll), loaded it before the ransomeware and ...

![2nd_method](https://user-images.githubusercontent.com/71389295/154583773-b2beb0b5-17f7-48cc-a8bc-c62cea4050b3.PNG)

again this made no sense to me because that dll was already in memory, I guess it's something I might understand in the future

## trying to generalize this solution

now everything is working fine and dandy, till you run it on a different computer, and you find out that `call rsi` isn't really located at 274 bytes after `RtlActivateActivationContextUnsafeFast` anymore, or doesn't exist at all (replaced by other variations of the `call` instruction). so I've tried exploring the possibility to making the solution as generalized as possible

my original bytes were like this

```asm
00007FF88EA6DCEA            | 4D:8BC6          | mov r8,r14
00007FF88EA6DCED            | 8BD3             | mov edx,ebx
00007FF88EA6DCEF            | 48:8BCF          | mov rcx,rdi
00007FF88EA6DCF2            | FFD6             | call rsi
```

and these are the bytes from another ntdll

```asm
00007FF88EA6DCEA            | 4D:8BC7          | mov r8,r15
00007FF88EA6DCED            | 8BD6             | mov edx,esi
00007FF88EA6DCEF            | 48:8BCE          | mov rcx,r14
00007FF88EA6DCEF            | 48:8BC4          | mov rax,r12
00007FF88EA6DCF2            | FFD6             | call rsi
```

I've noticed that most bytes are preserved between different versions, other ones only differ in a nibble or two (same instructions using different source registers), and other instructions that only exist in one version but not in another,  so I made [NibbleSigScan](https://github.com/0x00Jeff/NibbleSigScan) which is a simple program that allows you to wildcard nibbles, in the previous example, you can search for the pattern `0x4d, 0x8b, 0xc?, 0x8b, 0xd?` and it will match the first 2 instructions in both versions

after checking other version, I've found 5 patterns and wrote signatures for them. I've tried the signatures on about 30 version of ntdll (shoutout to folks who send me their dlls!), and they worked on all of them, except for one from a lab I had with windows 7 installed, but I figured there is no point in sopporting that one

now this *should* work on *most* ntdll version, but it's still advisable to run the second solution on a vm, incase there is a different version my sigatures don't work against (there probably exist more than one). as for the first method, it will work like charm as it's independent from the ntdll version

## another route

instead of having to patch `DllMain` to return right away, then manually calling `DllEntry` to initliaze the dll. in case of dealing with a dll that follows the standards of checking the `ul_reason_for_call` argument, one could patch the Dll entry point to call DllMain with a value other than `DLL_PROCESS_ATTACH` to inititialize the dll without encrypting the files, or patch the intructions in `DllMain` that calls the main functionality in the Dll (i.e DllMain creating threads on other functions), but the one in hand didn't

## lastly

as this article comes to an end, I'd like to thank hakivvi and harrold for helping with ideas and and encouragement, as well as the bois who are always offering their help such as jlbana, drifter and many others

oh, and the rasomware as well as the code for the solutions can be found [in this repo](https://github.com/0x00Jeff/sec-dojo/tree/main/ransomware101)

peace out
