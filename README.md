# ASM HalosGate Direct System Caller
Assembly HalosGate implementation that directly calls Windows System Calls, evades EDR User Land hooks, and displays the PPID of the explorer.exe process.

![](/imgs/asmHalosGatePoc.png)
+ In this screenshot the "NtQuerySystemInformation" & "NtAllocateVirtualMemory" NTDLL.DLL APIs systemcalls are discovered by using the HalosGate technique after failing to retrieve them via HellsGate technique due to EDR UserLand hooks.
+ After the systemcalls are resolved via the HellsGate and HalosGate method, they are are called directly. The code in NTDLL is never executed.

### To Do List
+ Obfuscate the strings for that are used for resolving the addresses of the NTDLL symbols
  + Or use hashing
+ ~Need to fix some bugs when switching from debug to release mode in visual studio's~ (Fixed 05/08/21)
+ ~Need to figure out how to properly overload the call to HellDescent()~ (Fixed 05/08/21)
+ Clean up the assembly functions, they are messy and could be better (Some cleanup 05/08/21)
+ ~Do better checking for the process image name so it doesnt conflict with other processes named explorer~ (Fixed 05/08/21)
+ Better error handling (Some better handling 05/08/21)
+ Make this into a cobalt strike beacon object file
+ Build on this project for process injection / syscall PS 
+ ~Use halos gate to handle EDR hooks.~ (Implemented in this project on 05/08/21)

### Credits / References
+ Reenz0h from @SEKTOR7net (Creator of the HalosGate technique )
  + This HalosGate project is based on the work of Reenz0h.
  + Most of the C techniques I use are from Reenz0h's awesome courses and blogs 
  + Best classes for malware development out there.
  + Creator of the halos gate technique. His work was the motivation for this work.
  + https://blog.sektor7.net/#!res/2021/halosgate.md 
  + https://institute.sektor7.net/
+ @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
  + Could not have made my implementation of HellsGate without them :)
  + Awesome work on this method, really enjoyed working through it myself. Thank you!
  + https://github.com/am0nsec/HellsGate 
  + Link to the Hell's Gate paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
+ Pavel Yosifovich (@zodiacon)
  + I learned how to correctly call NtQuerySystemInformation from Pavel's class on pentester academy. Full credits to Pavel for this. (BTW Pavel is an awesome teacher and I 100% recommend).
  + [Windows Process Injection for Red-Blue Teams - Module 2: NTQuerySystemInformation](https://www.pentesteracademy.com/video?id=1634)
