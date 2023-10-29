
### Oct 23 
Read from the lab tutorial that "theoretically, MacOS M1 works for our lab", and I tried, and failed for incompatible qemu version. A colleague of mine who got an Ubuntu on her Windows said it was quite easy to install a Ubuntu on Windows with Windows Subsystem for Linux (WSL), and there are tons of tutorials for that. So I decided to use the Windows from company issued laptop.

### Oct 24
The lab environment is ready.

In the evening I worked overtime using Sympy(a python library for Symbolic math) to do some dumb calculus so not much progress for learning OS today. 

Learned what `export PATH="~/something:$PATH` means.


### Oct 25
Learned ch1 and watched lectures about ch1 in the pase year.

Get clear about what lib(never thought it has something to do with OS) and OS do and how is memory prepared before function is called:
- std lib: provide panic handler & println! macro & `start` lang_item
- OS: 
, but not clear:
- Which part is lib's work and which part is OS's.
- What does Linker/ `os/src/linker.ld` do?


### Oct 26
Read Ch1 in v3 tutorial again. Learned about what exactly os does when the app is run in S-mode.


### Oct 27
Watched the first lecture in the Spring term: https://os2edu.cn/course/108/replay/5585
Learned Ch2, not really understand the usage of`lazy_static` in the initialization of APP_Manager. Also, the setting of  `scratch` was not clear.

### Oct 28
Went over Ch2 again, and especially read `_alltraps` and `_restore` line by line. This time I really get clear about how contexts are saved and restored and what role  `scratch` is playing. Also clarified why set `a0` to `sp` when running the next app.

In the evening I started Ch3.

### Oct 29


