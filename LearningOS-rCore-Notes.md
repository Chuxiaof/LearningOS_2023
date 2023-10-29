### Day1
#### ch1
##### Key Concepts:
- 面向单一编程语言的函数库的编程接口 (API, Application Programming Interface)
- 操作系统对运行在用户态软件提供服务的接口 (ABI, Application Binary Interface)
- SEE(?)对操作系统提供服务的接口 (SBI, Supervisor Binary Interface)

- 运行环境栈：
applications --(function call)-->Libraries --(system call)-->OS--(ISA)-->hardware

`x86_64-unknown-linux-gnu`：cpu架构-cpu厂商-操作系统-运行时
`riscv64gc-unknown-none-elf` cpu架构是 riscv64gc，厂商是 unknown，操作系统是 none， elf 表示没有标准的运行时库。没有任何系统调用的封装支持，但可以生成 ELF 格式的执行程序。

##### 主线任务：在`riscv64gc-unknown-none-elf` (bare metal)上运行`Hello, world!`
**step1.** 设置compiler使之支持编译裸机程序
具体步骤：
- 将rustc target平台设置为`riscv64gc-unknown-none-elf`
- 移除 main 对 std 的依赖: 在 `main.rs` 的开头加上一行 `#![no_std]` 告诉 Rust 编译器不使用 Rust 标准库 std 转而使用核心库 core（core库不需要操作系统的支持）
- 增加一个简单的 panic_handler:
```Rust
// os/src/lang_items.rs
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```
并在os/src/main.rs文件添加：
```Rust
// os/src/main.rs
#![no_std]
mod lang_items;
// ... other code
- 注释 println!
```
- 因为没有`start` lang_item，我们在 `main.rs` 的开头加入设置 `#![no_main]` 告诉编译器我们没有一般意义上的 `main` 函数，并将原来的 `main` 函数删除
Tools:  
`file`: 输出文件格式
`rust-objdump`: 反汇编导出汇编程序

**step2.** 构造：建立裸机程序的栈和SBI请求服务接口
程序能跑起来需要OS和Compiler达成的共识：地址
硬件加电后怎么让os跑起来的 ROM(一小段read only memory) -> bootloader -> OS start
为了让os镜像能够正确对接到 Qemu 和 RustSBI 上，我们提交给 Qemu 的内核镜像文件必须满足：该文件的开头即为内核待执行的第一条指令。
具体步骤：
1. 添加`_start`符号 （进入core后的第一条指令）
```Rust
 # os/src/entry.asm
     .section .text.entry
     .globl _start
 _start:
     li x1, 100
```
并且在 `main.rs` 中嵌入这段汇编代码：`global_asm!(include_str!("entry.asm"));`
2. 调整内核的内存布局
为了实现与 Qemu 正确对接，我们可以通过 **链接脚本** (Linker Script) 调整链接器的行为，使得最终生成的可执行文件的内存布局符合Qemu的预期，即内核第一条指令的地址应该位于 0x80200000 。
linker.ld作用：
第 1 行我们设置了目标平台为 riscv ；
第 2 行我们设置了整个程序的入口点为之前定义的全局符号 `_start`；
第 3 行定义了一个常量 `BASE_ADDRESS` 为 `0x80200000` ，也就是我们之前提到内核的初始化代码被放置的地址；
从第 5 行开始体现了链接过程中对输入的目标文件的段的合并。


3. 手动加载内核可执行文件
因为元数据无法被 Qemu 在加载文件时利用，且会使代码和数据段被加载到错误的位置，会导致 Qemu 内存 `0x80200000` 处无法找到内核第一条指令，也就意味着 RustSBI 无法正常将计算机控制权转交给内核。
使用如下命令可以丢弃内核可执行文件中的元数据得到内核镜像：
`rust-objcopy --strip-all target/riscv64gc-unknown-none-elf/release/os -O binary target/riscv64gc-unknown-none-elf/release/os.bin`

这些元数据能够帮助我们更加灵活地加载并使用可执行文件，比如在加载时完成一些重定位工作或者动态链接。不过由于 Qemu 的加载功能过于简单，我们只能将这些元数据丢弃再交给 Qemu 。从某种意义上可以理解为我们手动帮助 Qemu 完成了可执行文件的加载。

**静态链接与动态链接**
静态链接是指程序在编译时就将所有用到的函数库的目标文件链接到可执行文件中，这样会导致可执行文件容量较大，占用硬盘空间；而动态链接是指程序在编译时仅在可执行文件中记录用到哪些函数库和在这些函数库中用到了哪些符号，在操作系统执行该程序准备将可执行文件加载到内存时，操作系统会检查这些被记录的信息，将用到的函数库的代码和数据和程序一并加载到内存，并进行一些重定位工作，即对装入内存的目标程序中的指令或数据的内存地址进行修改，确保程序运行时能正确找到相关函数或数据。使用动态链接可以显著缩减可执行文件的容量，并使得程序不必在函数库更新后重新链接依然可用。
Qemu 模拟的计算机不支持在加载时动态链接，因此我们的内核采用静态链接进行编译。

**step3.** 为内核支持函数调用 -> 可以使用 Rust 语言来编写内核的各项功能
在进行函数调用的时候，我们通过 `jalr` 指令保存返回地址并实现跳转；而在函数即将返回的时候，则通过 `ret` 伪指令回到跳转之前的下一条指令继续执行。

由于函数调用，在控制流转移前后需要保持不变的寄存器集合称之为 **函数调用上下文** (Function Call Context)。
无论是调用函数还是被调用函数，都会因调用行为而需要两段匹配的保存和恢复寄存器的汇编代码，可以分别将其称为 **开场** (Prologue) 和 **结尾** (Epilogue)，它们会由编译器帮我们自动插入。编译器在进行后端代码生成时，知道在这两个场景中分别有哪些值得保存的寄存器，会优化掉一些无用的寄存器保存与恢复操作，提高程序的执行性能。

具体步骤：
1. 分配并使用启动栈
2. 对 `.bss` 段的清零
具体代码就不复制黏贴了。
OS正常运行前的初始化工作：建立栈空间和清零bss段

**step4.**  基于 SBI 服务完成输出和关机
RustSBI 功能：
1. 在计算机启动时进行它所负责的环境初始化工作，并将计算机控制权移交给内核。
2. 作为内核的执行环境，在内核运行时响应内核的请求为内核提供服务。
当内核发出请求时，计算机会转由 RustSBI 控制来响应内核的请求，待请求处理完毕后，计算机控制权会被交还给内核。从内存布局的角度来思考，每一层执行环境（或称软件栈）都对应到内存中的一段代码和数据，这里的控制权转移指的是 CPU 从执行一层软件的代码到执行另一层软件的代码的过程。
具体步骤：
1. 内核通过一种复杂的方式来“调用” RustSBI 的服务
1.1 定义`sbi_call`函数：
```Rust
// os/src/main.rs
 mod sbi;
 
 // os/src/sbi.rs
 use core::arch::asm;
 #[inline(always)]
 fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
     let mut ret;
     unsafe {
        asm!(
            "ecall",
            inlateout("x10") arg0 => ret,
            in("x11") arg1,
            in("x12") arg2,
            in("x17") which,
        );
    }
    ret
}
```
`sbi_call` 的函数签名: 
`which` 表示请求 RustSBI 的服务的类型（RustSBI 可以提供多种不同类型的服务）， 
`arg0` ~ `arg2` 表示传递给 RustSBI 的 3 个参数
RustSBI 在将请求处理完毕后，会给内核一个返回值，这个返回值也会被 `sbi_call` 函数返回。
1.2 在 `sbi.rs` 中我们定义 RustSBI 支持的服务类型常量，并包装`console_putchar`和`shutdown`函数
`SBI_CONSOLE_PUTCHAR` 可以用来在屏幕上输出一个字符
 `SBI_SHUTDOWN`关机服务
 ```Rust
// os/src/sbi.rs
pub fn console_putchar(c: usize) {
    sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
}
pub fn shutdown() -> ! {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    panic!("It should shutdown!");
}
```

2. 实现格式化输出 -> 用macro
3. 处理致命错误
之前定义的panic_handler其中只是一个死循环，会使得计算机卡在这里。借助前面实现的 `println!` 宏和 `shutdown` 函数，我们可以在 `panic` 函数中打印错误信息并关机。


### Day2
#### Ch2
人们希望一个应用程序的错误不要影响到其它应用程序、操作系统和整个计算机系统。这就需要操作系统能够终止出错的应用程序，转而运行下一个应用程序。这种 _保护_ 计算机系统不受有意或无意出错的程序破坏的机制被称为 **特权级** (Privilege) 机制，它让应用程序运行在用户态，而操作系统运行在内核态，且实现用户态和内核态的隔离，这需要计算机软件和硬件的共同努力。

- 当处理器执行当前特权模式不允许的操作时将产生一个**异常**，这些异常通常会产生自陷（trap）导致**下层执行环境接管控制权**

##### 实现应用程序
- 用户态下的应用程序， 有什么特别的？
- print/into test fault/Try to access privileged CSR 都是怎么实现的？
- `user/src/bin/*.rs` ：各个应用程序
- `user/src/*.rs` ：用户库（包括入口函数、初始化函数、I/O 函数和系统调用接口等）
- `user/src/linker.ld` ：应用程序的内存布局说明。

具体步骤:
1. 应用程序的内存布局
1.1 在 `lib.rs` 中我们定义了用户库的入口点 `_start`
1.2 手动清空需要零初始化的 `.bss` 段
1.3 在 `lib.rs` 中设置 weak `main`，如果在 `bin` 目录下找不到任何 `main` ，那么编译也能够通过，但会在运行时报错
1.4 在 `user/.cargo/config` 中，我们和第一章一样设置链接时使用链接脚本 `user/src/linker.ld` 。在其中我们做的重要的事情是：

- 将程序的起始物理地址调整为 `0x80400000` ，三个应用程序都会被加载到这个物理地址上运行；
- 将 `_start` 所在的 `.text.entry` 放在整个程序的开头，也就是说批处理系统只要在加载之后跳转到 `0x80400000` 就已经进入了 用户库的入口点，并会在初始化之后跳转到应用程序主逻辑；
- 提供了最终生成可执行文件的 `.bss` 段的起始和终止地址，方便 `clear_bss` 函数使用。

2. 应用程序发出的系统调用
2.1 在子模块 `syscall` 中，应用程序通过 `ecall` 调用批处理系统提供的接口，这个接口可以被称为 ABI 或者系统调用，站在应用程序的角度去使用即可。
在 RISC-V 调用规范中，和函数调用的 ABI 情形类似，约定寄存器 `a0~a6` 保存系统调用的参数， `a0` 保存系统调用的返回值。有些许不同的是寄存器 `a7` 用来传递 syscall ID，这是因为所有的 syscall 都是通过 `ecall` 指令触发的，除了各输入参数之外我们还额外需要一个寄存器来保存要请求哪个系统调用。由于这超出了 Rust 语言的表达能力，我们需要在代码中使用内嵌汇编来完成参数/返回值绑定和 `ecall` 指令的插入：
```Rust
// user/src/syscall.rs
use core::arch::asm;
fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        asm!(
           "ecall",
           inlateout("x10") args[0] => ret,
           in("x11") args[1],
           in("x12") args[2],
           in("x17") id
        );
    }
    ret
}
```
2.2 用`sys_write` 和 `sys_exit` 只需将 `syscall` 进行包装
3. 编译生成应用程序二进制码
这里简要介绍一下应用程序的自动构建。只需要在 `user` 目录下 `make build` 即可：
1. 对于 `src/bin` 下的每个应用程序，在 `target/riscv64gc-unknown-none-elf/release` 目录下生成一个同名的 ELF 可执行文件；
2. 使用 objcopy 二进制工具将上一步中生成的 ELF 文件删除所有 ELF header 和符号得到 `.bin` 后缀的纯二进制镜像文件。它们将被链接进内核并由内核在合适的时机加载到内存。

##### 实现批处理操作系统
在具体实现其批处理执行应用程序功能之前，本节我们首先实现该应用加载机制，也即：在操作系统和应用程序需要被放置到同一个可执行文件的前提下，设计一种尽量简洁的应用放置和加载方式，使得操作系统容易找到应用被放置到的位置，从而在批处理操作系统和应用程序之间建立起联系的纽带。具体而言，应用放置采用“静态绑定”的方式，而操作系统加载应用则采用“动态加载”的方式：
- 静态绑定：通过一定的编程技巧，把多个应用程序代码和批处理操作系统代码“绑定”在一起。
- 动态加载：基于静态编码留下的“绑定”信息，操作系统可以找到每个应用程序文件二进制代码的起始地址和长度，并能加载到内存中运行。
具体步骤：
1. 把应用程序的二进制镜像文件 -> 作为内核的数据段 -> 链接到 -> 内核里面
- 因此内核需要知道内含的应用程序的数量和它们的位置
- 这样才能够在运行时对它们进行管理并能够加载到物理内存
在 `cargo build` 的时候，由脚本 `os/build.rs` 控制生成的汇编代码 `link_app.S` 插入了五个应用程序的二进制镜像，应用程序的数量，和每个应用程序的起始和结束位置

2. 找到并加载应用程序二进制码
能够找到并加载应用程序二进制码的应用管理器 `AppManager` 是“邓式鱼”操作系统的核心组件。我们在 `os` 的 `batch` 子模块中实现一个应用管理器，它的主要功能是：

- 保存应用数量和各自的位置信息，以及当前执行到第几个应用了。
- 根据应用程序位置信息，初始化好应用所需内存空间，并加载应用执行。
```Rust
unsafe fn load_app(&self, app_id: usize) {
 2    if app_id >= self.num_app {
 3        panic!("All applications completed!");
 4    }
 5    println!("[kernel] Loading app_{}", app_id);
 6    // clear app area
 7    core::slice::from_raw_parts_mut(
 8        APP_BASE_ADDRESS as *mut u8,
 9        APP_SIZE_LIMIT
10    ).fill(0);
11    let app_src = core::slice::from_raw_parts(
12        self.app_start[app_id] as *const u8,
13        self.app_start[app_id + 1] - self.app_start[app_id]
14    );
15    let app_dst = core::slice::from_raw_parts_mut(
16        APP_BASE_ADDRESS as *mut u8,
17        app_src.len()
18    );
19    app_dst.copy_from_slice(app_src);
20    // memory fence about fetching the instruction memory
21    asm!("fence.i");
22}
    
```

2.1 设计应用管理器 `AppManager` 
应用管理器 `AppManager` 结构体定义如下：
能够找到并加载应用程序二进制码的应用管理器 `AppManager` 是“邓式鱼”操作系统的核心组件。
```Rust
// os/src/batch.rs

struct AppManager {
    num_app: usize,
    current_app: usize,
    app_start: [usize; MAX_APP_NUM + 1],
}
```
我们希望将 `AppManager` 实例化为一个全局变量，使得任何函数都可以直接访问。
由于Rust语言特性，最终使用`RefCell` ，并在他的基础上封装一个 `UPSafeCell`，它和 `RefCell` 一样提供内部可变性和运行时借用检查，只是更加严格：调用 `exclusive_access` 可以得到它包裹的数据的独占访问权。

2.2  来初始化`AppManager` 的全局实例 `APP_MANAGER`
- 以尽量少的 unsafe code 来初始化
- 初始化的逻辑：找到 `link_app.S` 中提供的符号 `_num_app` ，并从这里开始解析出应用数量以及各个应用的起始地址。注意其中对于切片类型的使用能够很大程度上简化编程。
- 使用`lazy_static`
	- 一般情况下，全局变量必须在编译期设置一个初始值
	- 但是有些全局变量依赖于运行期间才能得到的数据作为初始值
	- 这导致这些全局变量需要在运行时发生变化，即需要重新设置初始值之后才能使用 (?)
	- 借助 `lazy_static!` 声明了一个 `AppManager` 结构的名为 `APP_MANAGER` 的全局实例，且只有在它第一次被使用到的时候，才会进行实际的初始化工作。
2.3 `load_app`
- 将操作系统数据段的一部分数据（实际上是应用程序）复制到了一个可以执行代码的内存区域
- `fence.i`
##### 实现特权级的切换

- 特权级切换的硬件控制机制:
当 CPU 执行完一条指令（如 `ecall` ）并准备从用户特权级 陷入（ `Trap` ）到 S 特权级的时候，硬件会自动完成如下这些事情：
	- `sstatus` 的 `SPP` 字段会被修改为 CPU 当前的特权级（U/S）。
	- `sepc` 会被修改为 Trap 处理完成后默认会执行的下一条指令的地址。
	- `scause/stval` 分别会被修改成这次 Trap 的原因以及相关的附加信息。
	- CPU 会跳转到 `stvec` 所设置的 Trap 处理入口地址，并将当前特权级设置为 S ，然后从Trap 处理入口地址处开始执行。
	- 
- 用户栈与内核栈
	- 在正式进入 S 特权级的 Trap 处理之前，上面 提到过我们必须保存原控制流的寄存器状态，这一般通过内核栈来保存
	- 声明两个类型 `KernelStack` 和 `UserStack` 分别表示用户栈和内核栈，它们都只是字节数组的简单包装
	- 为两个类型实现了 `get_sp` 方法来获取栈顶地址
	- 数据结构 `TrapContext` 类似前面提到的函数调用上下文，即在 Trap 发生时需要保存的物理资源内容，并将其一起放在一个名为 `TrapContext` 的类型中，定义如下。里面包含所有的通用寄存器 `x0~x31` ，还有 `sstatus` 和 `sepc`：
```Rust
// os/src/trap/context.rs
#[repr(C)]
pub struct TrapContext {
    pub x: [usize; 32],
    pub sstatus: Sstatus,
    pub sepc: usize,
}
```

- Trap 管理：
包括：
1. 通过`ecall`U->S，保存被打断的应用程序的 Trap 上下文：`__alltraps`
2. trap分发与处理
3. 通过`sret`S->U，恢复被打断的应用程序的 Trap 上下文：`restore`


具体步骤：
1. Trap上下文的保存与恢复
1.1. 在批处理操作系统初始化的时候，我们需要修改 `stvec` 寄存器来指向正确的 Trap 处理入口点。引入了一个外部符号 `__alltraps` ，并将 `stvec` 设置为 Direct 模式指向它的地址。通过 `global_asm!` 宏将 `trap.S` 这段汇编代码插入进来。
```Rust
// os/src/trap/mod.rs
 
global_asm!(include_str!("trap.S"));

pub fn init() {
    extern "C" { fn __alltraps(); }
    unsafe {
        stvec::write(__alltraps as usize, TrapMode::Direct);
    }
}
```

1.2 我们在 `os/src/trap/trap.S` 中实现 Trap 上下文保存/恢复的汇编代码，分别用外部符号 `__alltraps` 和 `__restore` 标记为函数。
保存 Trap 上下文的 `__alltraps` 的实现：
- 在交换`sp`, `sscratch`之前，`sp`指向trap之前应用程序的栈底，第9行`csrrw sp, sscratch, sp`使得交换后，sp指向kernel 栈底，sscratch指向user栈底
- 将通用寄存器和`sstatus`, `sepc`保存在sp 上，所以是保存在内核栈
- Trap 处理函数 `trap_handler`需要去内核栈上找被保存下来的值，不能直接使用这些寄存器现在的值，因为它们可能已经被修改了
```Rust
# os/src/trap/trap.S
 2
 3.macro SAVE_GP n
 4    sd x\n, \n*8(sp)
 5.endm
 6
 7.align 2
 8__alltraps:
 9    csrrw sp, sscratch, sp
10    # now sp->kernel stack, sscratch->user stack
11    # allocate a TrapContext on kernel stack
12    addi sp, sp, -34*8 // grow stack
13    # save general-purpose registers
14    sd x1, 1*8(sp)
15    # skip sp(x2), we will save it later
16    sd x3, 3*8(sp)
17    # skip tp(x4), application does not use it
18    # save x5~x31
19    .set n, 5
20    .rept 27
21        SAVE_GP %n
22        .set n, n+1
23    .endr
24    # we can use t0/t1/t2 freely, because they were saved on kernel stack
25    csrr t0, sstatus
26    csrr t1, sepc
27    sd t0, 32*8(sp)
28    sd t1, 33*8(sp)
29    # read user stack from sscratch and save it on the kernel stack
30    csrr t2, sscratch
31    sd t2, 2*8(sp)
32    # set input argument of trap_handler(cx: &mut TrapContext)
33    mv a0, sp
34    call trap_handler
```
当 `trap_handler` 返回之后会从调用 `trap_handler` 的下一条指令开始执行，也就是从栈上的 Trap 上下文恢复的 `__restore` ：
```Rust
# os/src/trap/trap.S
 2
 3.macro LOAD_GP n
 4    ld x\n, \n*8(sp)
 5.endm
 6
 7__restore:
 8    # case1: start running app by __restore
 9    # case2: back to U after handling trap
10    mv sp, a0
11    # now sp->kernel stack(after allocated), sscratch->user stack
12    # restore sstatus/sepc
13    ld t0, 32*8(sp)
14    ld t1, 33*8(sp)
15    ld t2, 2*8(sp)
16    csrw sstatus, t0
17    csrw sepc, t1
18    csrw sscratch, t2
19    # restore general-purpuse registers except sp/tp
20    ld x1, 1*8(sp)
21    ld x3, 3*8(sp)
22    .set n, 5
23    .rept 27
24        LOAD_GP %n
25        .set n, n+1
26    .endr
27    # release TrapContext on kernel stack
28    addi sp, sp, 34*8
29    # now sp->kernel stack, sscratch->user stack
30    csrrw sp, sscratch, sp
31    sret
```
2. trap 的分发与处理 (逻辑比较简单掠过)
3. 实现系统调用功能
- `sys_write` 我们将传入的位于应用程序内的缓冲区的开始地址和长度转化为一个字符串 `&str` ，然后使用批处理操作系统已经实现的 `print!` 宏打印出来。注意这里我们并没有检查传入参数的安全性，即使会在出错严重的时候 panic，还是会存在安全隐患。这里我们出于实现方便暂且不做修补。
- `sys_exit` 打印退出的应用程序的返回值并同样调用 `run_next_app` 切换到下一个应用程序。
4. ## 执行应用程序
- 调用 `run_next_app` 函数切换到下一个应用程序。此时 CPU 运行在 S 特权级，而它希望能够切换到 U 特权级
- 在内核栈上压入一个为启动应用程序而特殊构造的 Trap 上下文，再通过 `__restore` 函数，就能让这些寄存器到达启动应用程序所需要的上下文状态。
- 在 `run_next_app` 函数中我们能够看到：
```Rust
// os/src/batch.rs
 2
 3pub fn run_next_app() -> ! {
 4    let mut app_manager = APP_MANAGER.exclusive_access();
 5    let current_app = app_manager.get_current_app();
 6    unsafe {
 7        app_manager.load_app(current_app);
 8    }
 9    app_manager.move_to_next_app();
10    drop(app_manager);
11    // before this we have to drop local variables related to resources manually
12    // and release the resources
13    extern "C" { fn __restore(cx_addr: usize); }
14    unsafe {
15        __restore(KERNEL_STACK.push_context(
16            TrapContext::app_init_context(APP_BASE_ADDRESS, USER_STACK.get_sp())
17        ) as *const _ as usize);
18    }
19    panic!("Unreachable in batch::run_current_app!");
20}
```
在内核栈上压入一个 Trap 上下文，其 `sepc` 是应用程序入口地址 `0x80400000` ，其 `sp` 寄存器指向用户栈，其 `sstatus` 的 `SPP` 字段被设置为 User 。

`push_context` 的返回值是内核栈压入 Trap 上下文之后的栈顶，它会被作为 `__restore` 的参数（这时我们可以理解为何 `__restore` 函数的起始部分会完成 sp←a0 ），这使得在 `__restore` 函数中 `sp` 仍然可以指向内核栈的栈顶。这之后，就和执行一次普通的 `__restore` 函数调用一样了。


### day3 
#### Ch3
key concepts:
1. 协作式操作系统
应用在执行 I/O 操作或空闲时，可以主动 _释放处理器_ ，让其他应用继续执行。当然执行 _放弃处理器_ 的操作算是一种对处理器资源的直接管理，所以应用程序可以发出这样的系统调用，让操作系统来具体完成。这样的操作系统就是支持 **多道程序** 或 **协作式多任务** 的协作式操作系统。

2. 抢占式操作系统
我们可以把一个程序的一次完整执行过程称为一次 **任务** (Task)，把一个程序在一个时间片（Time Slice）上占用处理器执行的过程称为一个 **任务片** (Task Slice)。操作系统对不同程序的执行过程中的 **任务片** 进行调度和管理，即通过平衡各个程序在整个时间段上的任务片数量，就能达到一定程度的系统公平和高效的系统效率。在一个包含多个时间片的时间段上，会有属于不同程序的多个任务片在轮流占用处理器执行，这样的操作系统就是支持 **分时多任务** 或 **抢占式多任务** 的抢占式操作系统。这种运行方式称为 **分时共享（Time Sharing）** 或 **抢占式多任务（Multitasking）** ，也可合并在一起称为 **分时多任务**。

**批处理与多道程序的区别是什么？**
- 相同：在一段时间内可以处理一批程序。
- 不同：对于批处理系统而言，内存中只放一个程序，处理器一次只能运行一个程序，只有在一个程序运行完毕后再把另外一个程序调入内存，并执行。即批处理系统不能交错执行多个程序。支持多道程序的系统的内存中可以放多个程序，一个程序在执行过程中，可以主动（协作式）或被动（抢占式）地放弃自己的执行，让另外一个程序执行。即支持多道程序的系统可以交错地执行多个程序，这样系统的利用率会更高。


批处理操作系统 – BatchOS：RustSBI（bootloader）完成基本的硬件初始化后，跳转到MultiprogOS起始位置，MultiprogOS首先进行正常运行前的初始化工作，即建立栈空间和清零bss段，然后通过改进的 AppManager 内核模块从app列表中把所有app都加载到内存中，并按指定顺序让app在用户态一个接一个地执行。app在执行过程中，会通过系统调用的方式得到MultiprogOS提供的OS服务，如输出字符串等。


**协作式多道程序操作系统 – CoopOS**
- 相对于MultiprogOS，CoopOS进一步改进了 AppManager 内核模块，把它拆分为负责加载应用的 Loader 内核模块和管理应用运行过程的 TaskManager 内核模块。
- 应用程序在运行时有自己所在的内存空间和栈，确保被切换时相关信息不会被其他应用破坏。
- 如果当前应用程序正在运行，则该应用对应的任务处于运行（Running）状态；如果该应用主动放弃处理器，则该应用对应的任务处于就绪（Ready）状态。


**分时多任务操作系统 – TimesharingOS**
- TimesharingOS最大的变化是改进了 Trap_handler 内核模块，支持时钟中断，从而可以抢占应用的执行。
- 并通过进一步改进 TaskManager 内核模块，提供任务调度功能，这样可以在收到时钟中断后统计任务的使用时间片，如果任务的时间片用完后，则切换任务。

不同点（即本章重点）：
- 多个应用同时放在内存中，所以他们的起始地址是不同的，且地址范围不能重叠
- 应用在整个执行过程中会暂停或被抢占，即会有主动或被动的任务切换
针对第一个不同情况，通过一个脚本 `build.py` 来针对每个应用程序修改链接脚本 `linker.ld` 中的 `BASE_ADDRESS` ，让编译器在编译不同应用时用到的 `BASE_ADDRESS` 都不同，且有足够大的地址间隔
针对第二个不同情况，需要实现任务切换，这就需要在上一章的 Trap 上下文切换的基础上，再加上一个 Task 上下文切换，才能完成完整的任务切换。
应用程序可以在用户态执行中主动暂停，这需要有新的系统调用 `sys_yield` 的实现来支持；为了支持抢占应用执行的抢占式切换，还要添加对时钟中断的处理。

关键数据结构：
`TaskContext`：表示应用执行上下文 + 具体完成上下文切换的汇编语言编写的 `__switch` 函数
`TaskControlBlock`：表示应用执行上下文的动态执行过程和状态（运行态、就绪态等
`TaskManager` ：全局变量实例 `TASK_MANAGER` 描述了应用程序初始化所需的数据， 而对 `TASK_MANAGER` 的初始化赋值过程是实现这个准备的关键步骤
通过对 `trap_handler` 函数中进行扩展，来完成在时钟中断产生时可能进行的任务切换。
`TaskManager` 数据结构的成员函数 `run_next_task` 来具体实现基于任务控制块的任务切换，并会具体调用 `__switch` 函数完成硬件相关部分的任务上下文切换。


##### 多道程序放置和加载
- 对相关模块进行了调整：在第二章中应用的加载和执行进度控制都交给 `batch` 子模块，而在第三章中我们将应用的加载这部分功能分离出来在 `loader` 子模块中实现，应用的执行和切换功能则交给 `task` 子模块。-
- 对每个应用被构建时使用的链接脚本 `linker.ld`进行调整，也就是要做到：应用知道自己会被加载到某个地址运行，而内核也确实能做到将应用加载到它指定的那个地址。
具体步骤：
1. 脚本定制工具 `build.py` 
我们不是直接用 `cargo build` 构建应用的链接脚本，而是写了一个脚本定制工具 `build.py` ，为每个应用定制了各自的链接脚本：
```Python
 # user/build.py
 2
 3 import os
 4
 5 base_address = 0x80400000
 6 step = 0x20000
 7 linker = 'src/linker.ld'
 8
 9 app_id = 0
10 apps = os.listdir('src/bin')
11 apps.sort()
12 for app in apps:
13     app = app[:app.find('.')]
14     lines = []
15     lines_before = []
16     with open(linker, 'r') as f:
17         for line in f.readlines():
18             lines_before.append(line)
19             line = line.replace(hex(base_address), hex(base_address+step*app_id))
20             lines.append(line)
21     with open(linker, 'w+') as f:
22         f.writelines(lines)
23     os.system('cargo build --bin %s --release' % app)
24     print('[build.py] application %s start with address %s' %(app, hex(base_address+step*app_id)))
25     with open(linker, 'w+') as f:
26         f.writelines(lines_before)
27     app_id = app_id + 1
```



2. 多道程序加载
所有的应用在内核初始化的时候就一并被加载到内存中。为了避免覆盖，它们自然需要被加载到不同的物理地址。这是通过调用 `loader` 子模块的 `load_apps` 函数实现的.
```Rust
// os/src/loader.rs
 2
 3 pub fn load_apps() {
 4     extern "C" { fn _num_app(); }
 5     let num_app_ptr = _num_app as usize as *const usize;
 6     let num_app = get_num_app();
 7     let app_start = unsafe {
 8         core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1)
 9     };
10     // clear i-cache first
11     unsafe { asm!("fence.i" :::: "volatile"); }
12     // load apps
13     for i in 0..num_app {
14         let base_i = get_base_i(i);
15         // clear region
16         (base_i..base_i + APP_SIZE_LIMIT).for_each(|addr| unsafe {
17             (addr as *mut u8).write_volatile(0)
18         });
19         // load app from data section to memory
20         let src = unsafe {
21             core::slice::from_raw_parts(
22                 app_start[i] as *const u8,
23                 app_start[i + 1] - app_start[i]
24             )
25         };
26         let dst = unsafe {
27             core::slice::from_raw_parts_mut(base_i as *mut u8, src.len())
28         };
29         dst.copy_from_slice(src);
30     }
31 }
// os/src/loader.rs
2
3 fn get_base_i(app_id: usize) -> usize {
4     APP_BASE_ADDRESS + app_id * APP_SIZE_LIMIT
5 }
```
 

3. 执行应用程序
这一过程与上章的描述类似。相对不同的是，操作系统知道每个应用程序预先加载在内存中的位置，这就需要设置应用程序返回的不同 Trap 上下文（Trap 上下文中保存了 放置程序起始地址的 `epc` 寄存器内容）：
- 跳转到应用程序（编号 i ）的入口点 entry
- 将使用的栈切换到用户栈


##### 任务切换
本节的重点是操作系统的核心机制—— **任务切换** ，在内核中这种机制是在 `__switch` 函数中实现的。 任务切换支持的场景是：一个应用在运行途中便会主动或被动交出 CPU 的使用权，此时它只能暂停执行，等到内核重新给它分配处理器资源之后才能恢复并继续执行。

 **任务**: 应用程序的一次执行过程（也是一段控制流）
  **计算任务片** 或 **空闲任务片** : 应用执行过程中的一个时间片段上的执行片段或空闲片段
 当应用程序的所有任务片都完成后，应用程序的一次任务也就完成了。从一个程序的任务切换到另外一个程序的任务称为 **任务切换** 。
为了确保切换后的任务能够正确继续执行，操作系统需要支持让任务的执行“暂停”和“继续”。 一旦一条控制流需要支持“暂停-继续”，就需要提供一种控制流切换的机制，而且需要保证程序执行的控制流被切换出去之前和切换回来之后，能够继续正确执行。需要保存与恢复的资源被称为 **任务上下文 (Task Context)** 。
```Rust
# os/src/task/switch.S
 2
 3.altmacro
 4.macro SAVE_SN n
 5    sd s\n, (\n+2)*8(a0)
 6.endm
 7.macro LOAD_SN n
 8    ld s\n, (\n+2)*8(a1)
 9.endm
10    .section .text
11    .globl __switch
12__switch:
13    # 阶段 [1]
14    # __switch(
15    #     current_task_cx_ptr: *mut TaskContext,
16    #     next_task_cx_ptr: *const TaskContext
17    # )
18    # 阶段 [2]
19    # save kernel stack of current task
20    sd sp, 8(a0)
21    # save ra & s0~s11 of current execution
22    sd ra, 0(a0)
23    .set n, 0
24    .rept 12
25        SAVE_SN %n
26        .set n, n + 1
27    .endr
28    # 阶段 [3]
29    # restore ra & s0~s11 of next execution
30    ld ra, 0(a1)
31    .set n, 0
32    .rept 12
33        LOAD_SN %n
34        .set n, n + 1
35    .endr
36    # restore kernel stack of next task
37    ld sp, 8(a1)
38    # 阶段 [4]
39    ret

// os/src/task/switch.rs
 2
 3global_asm!(include_str!("switch.S"));
 4
 5use super::TaskContext;
 6
 7extern "C" {
 8    pub fn __switch(
 9        current_task_cx_ptr: *mut TaskContext,
10        next_task_cx_ptr: *const TaskContext
11    );
12}
```

我们会调用该函数来完成切换功能而不是直接跳转到符号 `__switch` 的地址。因此在调用前后 Rust 编译器会自动帮助我们插入保存/恢复调用者保存寄存器的汇编代码。

仔细观察的话可以发现 `TaskContext` 很像一个普通函数栈帧中的内容。正如之前所说， `__switch` 的实现除了换栈之外几乎就是一个普通函数，也能在这里得到体现。尽管如此，二者的内涵却有着很大的不同。


##### 多道程序与协作式调度
一个应用会持续运行下去，直到它主动调用 `sys_yield` 系统调用来交出 CPU 使用权。内核将很大的权力下放到应用，让所有的应用互相协作来最终达成最大化 CPU 利用率，充分利用计算资源这一终极目标。
我们给出 `sys_yield` 的标准接口：
```Rust
/// 第三章新增系统调用（一）

/// 功能：应用主动交出 CPU 所有权并切换到其他应用。
/// 返回值：总是返回 0。
/// syscall ID：124
fn sys_yield() -> isize;
```

然后是用户库对应的实现和封装：
```Rust
// user/src/syscall.rs

pub fn sys_yield() -> isize {
    syscall(SYSCALL_YIELD, [0, 0, 0])
}

// user/src/lib.rs

pub fn yield_() -> isize { sys_yield() }
```
**任务控制块与任务运行状态**
- 任务运行状态：任务从开始到结束执行过程中所处的不同运行状态：未初始化、准备执行、正在执行、已退出
- 任务控制块(Task Control Block (TCB))：管理程序的执行过程的任务上下文，控制程序的执行与暂停
- 任务相关系统调用：应用程序和操作系统之间的接口，用于程序主动暂停 `sys_yield` 和主动退出 `sys_exit`
```Rust
// os/src/task/task.rs

#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    pub task_status: TaskStatus,
    pub task_cx: TaskContext,
}
```

`0~num_app-1` 来访问得到每个应用的控制状态。我们的任务就是找到 `current_task` 后面第一个状态为 `Ready` 的应用。因此从 `current_task + 1` 开始循环一圈，需要首先对 `num_app` 取模得到实际的下标，然后检查它的运行状态。


接下来看看 `run_next_task` 的实现：
```Rust
 1// os/src/task/mod.rs
 2
 3fn run_next_task() {
 4    TASK_MANAGER.run_next_task();
 5}
 6
 7impl TaskManager {
 8    fn run_next_task(&self) {
 9        if let Some(next) = self.find_next_task() {
10            let mut inner = self.inner.exclusive_access();
11            let current = inner.current_task;
12            inner.tasks[next].task_status = TaskStatus::Running;
13            inner.current_task = next;
14            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
15            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
16            drop(inner);
17            // before this, we should drop local variables that must be dropped manually
18            unsafe {
19                __switch(
20                    current_task_cx_ptr,
21                    next_task_cx_ptr,
22                );
23            }
24            // go back to user mode
25        } else {
26            panic!("All applications completed!");
27        }
28    }
29}
```

当被任务切换出去的应用即将再次运行的时候，它实际上是通过 `__switch` 函数又完成一次任务切换，只是这次是被切换进来，取得了 CPU 的使用权。
类似构造 Trap 上下文的方法，内核需要在应用的任务控制块上构造一个用于第一次执行的任务上下文。我们是在创建 `TaskManager` 的全局实例 `TASK_MANAGER` 的时候来进行这个初始化的。


##### 分时多任务系统与抢占式调度
**时间片轮转算法** (RR, Round-Robin)：维护一个任务队列，每次从队头取出一个应用执行一个时间片，然后把它丢到队尾，再继续从队头取出一个应用，以此类推直到所有的应用执行完毕。

在 RISC-V 架构语境下， **中断** (Interrupt) 和我们第二章中介绍的异常（包括程序错误导致或执行 Trap 类指令如用于系统调用的 `ecall` ）一样都是一种 Trap ，但是它们被触发的原因却是不同的。对于某个处理器核而言， 异常与当前 CPU 的指令执行是 **同步** (Synchronous) 的，异常被触发的原因一定能够追溯到某条指令的执行；而中断则 **异步** (Asynchronous) 于当前正在进行的指令，也就是说中断来自于哪个外设以及中断如何触发完全与处理器正在执行的当前指令无关。

RISC-V 的中断可以分成三类：
- **软件中断** (Software Interrupt)：由软件控制发出的中断
- **时钟中断** (Timer Interrupt)：由时钟电路发出的中断
- **外部中断** (External Interrupt)：由外设发出的中断

另外，相比于异常，中断和特权级之间的联系更为紧密，可以看到这三种中断每一个都有 M/S 特权级两个版本。中断的特权级可以决定该中断是否会被屏蔽，以及需要 Trap 到 CPU 的哪个特权级进行处理。

在判断中断是否会被屏蔽的时候，有以下规则：
- 如果中断的特权级低于 CPU 当前的特权级，则该中断会被屏蔽，不会被处理；
- 如果中断的特权级高于与 CPU 当前的特权级或相同，则需要通过相应的 CSR 判断该中断是否会被屏蔽。

以内核所在的 S 特权级为例，中断屏蔽相应的 CSR 有 `sstatus` 和 `sie` 。
- `sstatus` 的 `sie` 为 S 特权级的中断使能，能够同时控制三种中断，如果将其清零则会将它们全部屏蔽。
- 即使 `sstatus.sie` 置 1 ，还要看 `sie` 这个 CSR，它的三个字段 `ssie/stie/seie` 分别控制 S 特权级的软件中断、时钟中断和外部中断的中断使能。
- 比如对于 S 态时钟中断来说，如果 CPU 不高于 S 特权级，需要 `sstatus.sie` 和 `sie.stie` 均为 1 该中断才不会被屏蔽；如果 CPU 当前特权级高于 S 特权级，则该中断一定会被屏蔽。

如果中断没有被屏蔽，那么接下来就需要软件进行处理，而具体到哪个特权级进行处理与一些中断代理 CSR 的设置有关。默认情况下，所有的中断都需要到 M 特权级处理。而通过软件设置这些中断代理 CSR 之后，就可以到低特权级处理，但是 Trap 到的特权级不能低于中断的特权级。事实上所有的中断/异常默认也都是到 M 特权级处理的。

- U 特权级的应用程序发出系统调用或产生错误异常都会跳转到 S 特权级的操作系统内核来处理；
- S 特权级的时钟/软件/外部中断产生后，都会跳转到 S 特权级的操作系统内核来处理。


中断产生后，硬件会完成如下事务：
- 当中断发生时，`sstatus.sie` 字段会被保存在 `sstatus.spie` 字段中，同时把 `sstatus.sie` 字段置零，这样软件在进行后续的中断处理过程中，所有 S 特权级的中断都会被屏蔽；
- 当软件执行中断处理完毕后，会执行 `sret` 指令返回到被中断打断的地方继续执行，硬件会把 `sstatus.sie` 字段恢复为 `sstatus.spie` 字段内的值。

也就是说，如果不去手动设置 `sstatus` CSR ，在只考虑 S 特权级中断的情况下，是不会出现 **嵌套中断** (Nested Interrupt) 的。嵌套中断是指在处理一个中断的过程中再一次触发了中断。由于默认情况下，在软件开始响应中断前， 硬件会自动禁用所有同特权级中断，自然也就不会再次触发中断导致嵌套中断了。



一个 64 位的 CSR `mtime`：时钟，用来统计处理器自上电以来经过了多少个内置时钟的时钟周期。
一个 64 位的 CSR `mtimecmp`：计时器，一旦计数器 `mtime` 的值超过了 `mtimecmp`，就会触发一次时钟中断。

调用RustSBI预留的接口来间接实现计时器的控制：
```Rust
// os/src/timer.rs

use riscv::register::time;

pub fn get_time() -> usize {
    time::read()
}
```

新增一个系统调用，方便应用获取当前的时间：
```Rust
/// 第三章新增系统调用（二)

/// 功能：获取当前的时间，保存在 TimeVal 结构体 ts 中，_tz 在我们的实现中忽略
/// 返回值：返回是否执行成功，成功则返回 0
/// syscall ID：169
fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize;

#[repr(C)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}
```
