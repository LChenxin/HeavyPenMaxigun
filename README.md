# HeavyPenMaxigun

把 Helldivers 2 的 **M-1000 Maxigun** 穿甲从 `3/3/3/0`（中甲）提到 `4/4/4/0` ——
也就是 MG-206 HMG 和 APW-1 AMR 在本作中已有的档位。

基于 [Bingus Shared Loader](https://github.com/CowboyBingus/BingusSharedLoader)
v15 的第三方 addon API。纯运行时内存改写，**不修改任何游戏文件**，卸载即恢复。

个人学习用。仓库里除了成品，主要价值是**逆向过程的记录**和一套可复用的分析工具。

---

## 它改了什么

```
damage_settings 缓冲区  ←  game.dll+0x02791748
Maxigun 记录 @ 缓冲区偏移 0x02664

  +0x0C  3 → 4      穿甲 正面
  +0x10  3 → 4      穿甲 小角度
  +0x14  3 → 4      穿甲 大角度
```

一共 12 字节。伤害、耐久伤害、极限角穿甲、拆解/硬直/击退全部不动。

写之前要过四道关，任何一条不符就什么都不写：

1. `helldivers2.exe` 和 `game.dll` 的 SHA256
2. 缓冲区身份（实例数 2、`LDLD` 魔数、version 1、type `0xEB1433DA`）
3. **两条锚点记录逐字节比对** —— MG-206 HMG 和 APW-1 AMR，用来确认表没挪位
4. 目标记录必须正好是 `123, 80, 18, 3, 3, 3, 0, 10, 15, 12`

写入只进 `MEM_COMMIT + MEM_PRIVATE + PAGE_READWRITE` 页，拒绝可执行页和映射的模块页。
回读不符会回滚。每 600 帧复查一次，游戏若重载设置会自动重新应用。

---

## 逆向过程

### 1. game.dll 加了壳，静态分析这条路是死的

```
section            VA    virt size     raw size   entropy
           0x00001000     31839187      8635904    8.0000   打包的 .text
           0x02394000      7622788       125952    7.9976   全局数据段
.winlice   0x02CEE000      8806400            0    0.0000   WinLicense 标志
.boot      0x03554000      4925952      4925952    7.8412   解壳 stub，入口在此
```

节名被抹、熵满值、入口点在 `.boot`，全文件搜不到一个明文字符串（`LDLD`、`.dl_bin`、
`dl_library` 全部零命中）。**所有分析必须在运行时做。** `tools/pe_probe.py` 可复现。

这也解释了为什么所有同类 mod 都先校验模块 SHA256 再信任 RVA —— 那些 RVA 只在解壳后成立。

### 2. 配置数据是 datalibrary 序列化的

`data/game/` 下 54 个 `.dl_bin`，磁盘上加密（熵 ~8.0），解密进堆后是明文 DL 布局：

```
base +0   u32  instance count
     +4   u32  0x444C444C  'LDLD'     ← 每个实例的头从这里开始
     +8   u32  version (1)
     +12  u32  root type id
     +16  u32  payload size
     +20  u32  is_64_bit_ptr (1)
     +24  u32  reserved (0)
     +28  root: [ptr to items][u32 item count]
     ...  下一个实例头紧跟在 payload 之后
```

### 3. 大小指纹：不解密也能认出缓冲区

```
generated_stratagem_settings.dl_bin = 79,344 字节（磁盘）
BetterStratagemBounce 验证的缓冲区   = 79,296 字节（内存）
                                差  =     48        加密框架
```

**解密后大小 = 文件大小 − 48**。最初只有这一个样本支持，后来在内存里找到的 14 个
缓冲区全部命中指纹、零未匹配，假设才算站住。`tools/gen_fingerprints.py` 生成该表。

### 4. 在内存里找到这些表

样本 mod 硬编码的全局指针全挤在 `0x02394000` 那个可写数据段里：

```
0x276C190 player manager     0x276C3D0 mission global
0x276C468 equipment manager  0x276C8D0 jump pack manager
0x276CA30 avatar manager     0x276CAD0 attachment manager
0x276F0C0 entity owner       0x2791F68 stratagem buffer ptr
```

所以扫这 7.6 MB 找出所有指向 DL 缓冲区的指针即可，得到的是**稳定 RVA**。
`mods/hpmg/dl_hunt.lua` 干这件事，并把命中的缓冲区 dump 到磁盘供离线分析。

代价是这条路只能找到 16 个缓冲区 —— 另外 38 个（包括 45 MB 的 `entities`）**不经过
这个全局数组**。dl_hunt 因此还带一个全内存签名 sweep 作为后备。

### 5. 武器数值的真实位置

穿甲**不在**弹丸记录里。弹丸记录的 `+0x3C` 是一个 damage-info id，指向
`damage_settings` 里的一段 40 字节：

```
  +0x00  id            +0x04  伤害        +0x08  耐久伤害
  +0x0C  穿甲 正面      +0x10  穿甲 小角度
  +0x14  穿甲 大角度    +0x18  穿甲 极限角
  +0x1C  拆解          +0x20  硬直        +0x24  击退
```

这个布局是**反解**出来的：HMG-AMR-Rounds-v3 那个 mod 随包附了一份 REPORT.md，
公开了两条记录的完整数值。在缓冲区里找哪两段字节长这样，布局就出来了 ——
而且两条都精确重现：

```
0x03B2C  id 199  150/35   4/4/4/0  15/25/20   MG-206 HMG
0x03B78  id 200  450/225  4/4/4/0  20/25/25   APW-1 AMR
0x02664  id 123   80/18   3/3/3/0  10/15/12   M-1000 Maxigun
```

Maxigun 那条的识别依据：伤害 80、耐久 18、穿甲 3/3/3/0（中甲/中甲/中甲/无甲）
三项与公开数据一致，且 `80, 18` 这个相邻字节对在整个 48 KB 缓冲区里**只出现一次**。
另外只有 1 条弹丸记录引用 damage-info 123，不存在连带影响。

> **保留意见**：`damage_settings` 里没有名字字符串，识别完全建立在「数值组合唯一」
> 上，**不是按名字匹配**。证据很强，但性质不同。

弹丸记录本身已确认的字段（同样由上述报告交叉验证）：

```
+0x00 类型id  +0x20 速度  +0x24 质量  +0x28 阻力  +0x2C 重力系数
+0x3C damage-info id   +0xA8 表面冲击  +0xAC 跳弹冲击  +0xE8 命中效果类型
```

`damage_settings` 实例 0（32 字节）是 floats `[25,60,80,90,25,60,80,90]` ——
四个入射角阈值，对应「正面 / 小角度 / 大角度 / 极限角度」。

### 6. 弹匣容量为什么改不了

它在**武器组件**数据里。HMG-AMR 那份报告记录了作者两次实游测试，证明该数据
**不驻留在可读运行时内存中**（v1 和 v2 都栽在这，v3 才改走弹丸记录）。
本项目 dump 的所有缓冲区里也确实没有它。

---

## 环境

| 项目 | 值 |
|---|---|
| 游戏 | Steam build 24826606 / EXE `1.8.45317.0` |
| helldivers2.exe | SHA256 `A09FF526…88CC3` |
| game.dll | SHA256 `CC75948D…57470C` |
| Python | 3.14（Windows 上用 `py -3`） |
| 依赖 | 打包只用标准库；测试和分析工具需要 venv |

**游戏一更新，这两个哈希就会变，本仓库所有偏移都必须重新验证。** mod 届时会
拒绝写入并在日志里说明，不会写坏东西。

---

## 构建与测试

```powershell
py -3 -B build.py                      # 构建全部 enabled 的 mod
py -3 -B build.py --only heavy_pen_maxigun
.venv\Scripts\python.exe tests\run.py  # Lua 测试（内嵌 LuaJIT 2.1）
```

venv 一次性搭建：

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install capstone pefile lupa
```

打包器不在本仓库 —— 它是 Bingus Shared Loader 自己的 `scripts/build_addon.py`，
这样归档格式永远跟着 loader 版本走，不会漂移。二选一提供：

* 把 BingusSharedLoader 源码 zip 放到 `samplefile/BingusSharedLoader-main.zip`
* 或 clone 一份后指过去：`set HPMG_BSL_SOURCE=C:\path\to\BingusSharedLoader`

缺文件时 `build.py` 会把这两条打印出来。

### 测试覆盖

```
tests/test_heavy_pen_maxigun.lua   82 项   成品：拒绝路径、只写 12 字节、回滚、真实 Win32 层
tests/test_dl_hunt.lua             44 项   缓冲区发现：近失上报、合成内存 sweep
tests/test_dl_probe.lua            29 项   DL 解析器：接受与拒绝两侧
tests/test_dl_dump.lua             28 项   dump 格式 + 跨语言契约
```

最后一项是 Lua 写 dump 头、Python 读 dump 头。两边格式一旦漂移不会报错，只会
**安静地产出垃圾分析** —— 所以让 Lua 测试真写一个文件，Python 解析器真读一遍。

`test_heavy_pen_maxigun.lua` 里有一组直接驱动**真实 Windows API 层**的检查。
之前所有测试都把那层 stub 掉了，结果一个 `void *` 指针算术错误躲过 65 项检查、
进游戏才崩。补上之后我把 bug 改回去确认新测试真能抓住它。

---

## 部署

1. 关闭游戏。
2. 把 `dist/*.zip` 导入 Arsenal 或 HD2MM，启用。
3. **Bingus Shared Loader 必须排在最后**（Arsenal 默认优先级下放列表底部；
   若开了 first-mod priority 则放最前）。loader 要赢得 Wwise 启动脚本的覆盖权。
4. Purge → Deploy，启动游戏。
5. 验证：

```powershell
py -3 -B tools/inspect_patches.py
```

会依次输出：构建哈希是否匹配 → 每个 `9ba626afa44a3aa3.patch_N` 里有哪些资源
（自己的标 `<-- YOURS`）→ loader 日志里每个模块的状态。

成功时 `%LOCALAPPDATA%\CowboyBingus\Helldivers2\Logs\HeavyPenMaxigun.log` 会写：

```
applied: penetration 3/3/3/0 -> 4/4/4/0 on damage-info 123
```

---

## 仓库结构

```
mods/hpmg/heavy_pen_maxigun.lua   成品
mods/hpmg/dl_hunt.lua             找 DL 缓冲区 + dump（默认停用）
mods/hpmg/dl_probe.lua            L2 只读探针，被 dl_hunt 取代，留作过程记录
mods/hpmg/dl_dump.lua             L2.5 缓冲区 dump，同上
mods/hpmg/hello_test.lua          最小 addon，用来验证加载链路
mods.json                         命名空间、游戏路径、每个 mod 的 GUID
build.py                          打包成管理器可导入的 ZIP
tests/run.py                      在内嵌 LuaJIT 2.1 里跑 tests/*.lua
tools/inspect_patches.py          看游戏里实际部署了什么 + 读 loader 日志
tools/analyze_dl.py               离线分析 dump：推步长、指纹匹配、解字符串
tools/pe_probe.py                 game.dll 的 PE 布局和节熵
tools/dl_scan.py                  扫描 .dl_bin 里的 DL 实例
tools/gen_fingerprints.py         生成大小指纹表
samplefile/  vendor/  dist/  .venv/     均不进 git
```

`samplefile/` 放参考用的第三方 mod 包。**不进仓库** —— 那是别人的作品，
不该由这里重新分发。

---

## 写自己的 addon 时要注意

- **入口脚本必须是纯文本 UTF-8 无 BOM**。编译会抹掉 `-- HD2-Addon:` 声明注释，
  discovery 就找不到它。要用编译后的代码，就在入口里 `require` 另一个资源。
- **GUID 一经发布不要改**。管理器靠 GUID 认 mod。
- **初始化要幂等**，用 `rawget(_G, 'YourGlobal')` 守卫。
- **包装 `update` 回调要记住前一个 owner**，用完只在自己仍持有时归还所有权。
- **FFI 里重复声明函数没问题，重复定义 struct 会报错** —— 多个 mod 共享同一个
  LuaJIT VM，struct 标签要起独有名字。
- **`MEMORY_BASIC_INFORMATION.base` 是 `void *`**，LuaJIT 不允许对它做指针算术。
  算 `size - (cursor - base)`，不要算 `base + size`。
- **只写数据页**，别注入 DLL、别改代码段。

## 方法论

1. **任何工具在用之前，先拿已知答案验一遍。** 本项目的分析器第一件事是重现
   BetterStratagemBounce 公开的 147 个 stratagem 标志值，必须全中才算可信。
   这是区分「真的找到了」和「凑巧对上了」的唯一办法。
2. **要报告扔掉了什么，不只是找到了什么。** 曾怀疑扫描器的实例上限静默吃掉了
   目标缓冲区；加上近失上报后跑出 `near_misses = 0`，假设被干净否掉。
3. **测试要覆盖真正接触现实的那一层。** 见上面那个 `void *` 的教训。

## 免责

游戏带 GameGuard，且是联机游戏。数据类改动在多人局里 host/client 行为可能不一致，
建议单人或私人房使用。自负风险。
