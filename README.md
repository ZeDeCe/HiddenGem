# HiddenGem
A weaponization of DeepSleep, a variant of Gargoyle for x64 that hides memory artifacts using ROP

This project is completely based on the research of both [@waldoirc](https://twitter.com/waldoirc) and his [blog](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/); and [@thefLink](https://github.com/thefLink) and [DeepSleep](https://github.com/thefLink/DeepSleep).
This implementation only uses their techniques to create a basic malware to better understand evasion techniques.

The DeepSleep project included is an edited version of the original.

## Description
The sole reason for this being created is to learn more about ROP chains and understand this amazing injection technique. I've only added a few features to the actual POC of DeepSleep and changed it a bit.

I tried going a little different to the POC created by @waldo-irc (a cobaltstrike agent injection) and instead created a ticking "botnet"-esque time bomb malware.
Although this is not a part included in the project, the project is made to wait for a certain trigger, meanwhile hiding the malware, and finally striking by releasing the bomb.

Other than the base DeepSleep project, this project includes:
- An [Earlybird](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) loader that loads the DeepSleep binary into memory and runs it
- A cleanup procedure that cleans the DeepSleep method
- Encryption of both the malware itself and the DeepSleep binary
- A way to pass arguments to the main method of the DeepSleep binary

## Usage
Using mingw, use the ```make``` command on the main folder of the project
This will create a ```build``` folder

## To Add
- An actual time bomb malware
- Automatic encryption of malware on compile
- Load the DeepSleep binary from an encrypted resource

## Further research
This project evades (while hidden) moneta and pe-sieve on most flags, but can be detected using the /threads flag on pe-sieve.
If the thread stack can be manipulated through the ROP chains to use some JOP and avoid VirtualProtect and outside addresses this can be avoided.
This is still detected by everything that detects the DeepSleep project, as stated in the project's page.
