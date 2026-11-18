# PCSG00510：EBOOT、字库及码表分析

分析对象为《Starry☆Sky ～Spring Stories～》日版 PCSG00510。
本次实际运行 Ghidra 12.1.3 + VitaLoaderRedux 1.09，并从本作的 EBOOT 函数恢复字形索引、Unicode 转码表和剧情解压算法。

## 提取成果

| 内容 | 结果 | 文件 |
| --- | --- | --- |
| 字库图像 | 2048×4096，8192 个 32×32 槽位，16 色 RGBA | [font32_atlas.png](../06_中文字体/original_font/font32_atlas.png) |
| 字形预览 | 全角、半角、假名、汉字对应抽查 | [font_preview.png](../06_中文字体/original_font/font_preview.png) |
| 游戏编码→槽位表 | 8350 行，含单字节与双字节别名、图集坐标、VTX 偏移和 Unicode 别名 | [game_code_table.tsv](../06_中文字体/original_font/game_code_table.tsv) |
| 逐槽字库清单 | 全部 8192 槽，包含像素覆盖和尾部标志值 | [font_slots.tsv](../06_中文字体/original_font/font_slots.tsv) |
| 文本工具用码表 | 7120 个可由 CP932 命名的编码条目 | [game_cp932.tbl](../06_中文字体/original_font/game_cp932.tbl) |
| EBOOT 原始 Unicode 转码表 | 65536×u16LE，131072 字节；含 9485 个非 FFFF 映射 | [eboot_unicode_to_sjis.tsv](../06_中文字体/original_font/eboot_unicode_to_sjis.tsv)、[原始二进制](../06_中文字体/original_font/eboot_unicode_to_sjis.bin) |
| 剧情解压数据 | 4886272 字节，173 个目录条目，目录完整覆盖文件 | [sn_decompressed.bin](../04_日文原文/sn_decompressed.bin)、[目录](../04_日文原文/sn_entries.tsv) |
| 正文及标签 | 48871 条：0x45 正文 28635 条；0x46 人名／标签 20236 条 | [sn_messages.tsv](../04_日文原文/sn_messages.tsv)、[阅读版](../04_日文原文/sn_readable.txt) |
| 选项文本 | 312 项，包含剧情选项及调试菜单 | [sn_choices.tsv](../04_日文原文/sn_choices.tsv) |
| EBOOT 日文 UTF-8 串 | 306 条，保留地址、文件偏移及原始字节 | [eboot_utf8_japanese.tsv](../04_日文原文/eboot_utf8_japanese.tsv) |

TSV 使用 UTF-8 BOM，包含原始字节和偏移，便于用 Excel 或文本工具核对。

## 解密与身份校验

`01_游戏文件` 内的 EBOOT、VTX、CPK 和 sn.bin 原先均为 PFS 密文，直接导入 Ghidra 不会得到有效代码。
使用游戏自己的 `sce_sys/package/work.bin`，结合本地 PFS 工具和 Vita3K 的原生 F00D 算法，恢复出 SELF 及资源。F00D 适配器仅绑定 127.0.0.1，授权数据没有发送到外部服务。

SELF 再转换为未重定位 ELF，输出文件位于：

`02_解包资源/PCSG00510_decrypted/PCSG00510.elf`

ELF SHA-256：`f01c8faf793342e147f2a8ab09aae7e2f1dd6c6ef6cded995cdbffb6e2130d18`

该摘要与零售 SELF 内记录的 ELF 摘要完全一致。EBOOT、font32.vtx、sn.bin 的输入文件仍与 `00_原始备份` 逐文件哈希一致。详细记录见 [decryption_report.json](ghidra/decryption_report.json)。

## Ghidra 工程与关键函数

工程：`03_文件结构分析/ghidra/project/StarrySky_PCSG00510.gpr`

语言为 `ARM:LE:32:v7`，镜像基址 `0x81000000`，本作关键代码使用 Thumb 指令。
自动分析登记 2239 个函数；首轮导出 2238 个函数的反编译结果。部分大型函数有反编译警告，不能将全部自动生成的 C 代码视为已人工确认。
本次重点确认的 18 个函数已在 Ghidra 工程内重命名、写入注释，并另存到 [key_functions](ghidra/key_functions/key_functions.tsv)。

| 地址 | 名称／作用 | 证据 |
| --- | --- | --- |
| 0x8100CBB4 | SS_LoadFontAtlas | 引用 `font32.vtx`，交给通用 VTX 加载器，字体句柄位于 0x81116EC4 |
| 0x81015B8A | SS_LoadVtxOrXtxTexture | 按 `vtx`／`xtx` 魔数分流；本文件进入 0x810158F4 |
| 0x810158F4 | SS_LoadVtxTexture | VTX 类型 0：复制 +0x20 的 0x40 字节调色板、+0x60 的 width×height/2 字节像素，以及每槽一个尾部字节 |
| 0x8100D0B2 | SS_QueueShiftJisGlyph | 字符→字形索引；用原始机器码验证过全部测试编码 |
| 0x8100DCA8 | SS_DrawShiftJisGlyph | 相同的字符索引公式 |
| 0x8100DFB8 | SS_DrawShiftJisGlyphAtPosition | 相同的字符索引公式，带位置绘制 |
| 0x81017192 | SS_RenderFontGlyphQuad | x=(index%64)×32，y=(index/64)×32；UV 分别除以 2048、4096 |
| 0x8100D6CE | SS_DecodeUtf8BmpCharacter | 解码一个 UTF-8 字符到 16 位 Unicode |
| 0x8100D77E | SS_Utf8OrSjisToGameEncoding | 用 0x810B8A54 的表将 Unicode 转为 Shift-JIS，并可透传原有 SJIS 字节 |
| 0x8100D8AC | SS_ConvertTextViaTemporaryBuffer | 分配临时缓冲后调用转码函数 |
| 0x81014D50 | SS_StartupAndLoadScenario | 引用 `sn.bin`，调用解压函数，输出到 0x83D6D6A4 |
| 0x8104DA28 | SS_DecompressLzss | 本作 LZSS 解压例程 |
| 0x8102C956 | SS_ReplayVmUntilCommandCounter | 通过 0x810B877C 的函数指针表分发字节码 |
| 0x810307B2 | SS_VmText45 | 0x45 文本指令：窗口、可选消息 ID、NUL 终止串 |
| 0x8103192A | SS_VmText46 | 0x46 文本指令；窗口 13 常用于人名 |
| 0x81032962 | SS_VmText47 | 0x47 文本指令，另一种对齐绘制 |
| 0x81029480 | SS_VmChoice31 | 0x31 选项指令 |
| 0x81029EDE | SS_VmChoice32 | 0x32 选项重放指令 |

资源字符串交叉引用另见 [resource_xrefs.tsv](ghidra/key_functions/resource_xrefs.tsv)。

## 字库文件结构

| 文件偏移 | 大小 | 内容 |
| --- | --- | --- |
| 0x00 | 0x20 | `vtx\0` 文件头；+4 类型字节为 0，+5 小端标志为 1；宽高 2048×4096 |
| 0x20 | 0x40 | 16 项 RGBA 调色板，每项 4 字节 |
| 0x60 | 0x400000 | 4bpp 图像；低半字节在前；每个 32×32 字形连续占 512 字节 |
| 0x400060 | 0x2000 | 8192 个尾部标志字节，本次保留原值 |

导出的 PNG 将连续字形按 64 列、128 行排列。第 i 个字形的 VTX 文件偏移为 `0x60+i×512`。
调色板既有半透明黑边，也有不透明灰度；直接把半字节乘以 17 会丢失原始描边与透明度。

字体有 39 个无像素槽位，尾部标志为 0 的槽位也恰为 39 个；标志的引擎语义尚未进一步确认。
其中包含全角／半角空格，不能直接把所有无像素槽位都当作可覆盖的汉化空间。另有未分配码位显示占位点，也不能仅凭 Unicode 为空就认为没有字形。

## 字符索引公式

单字节：ASCII 使用 `index=byte+0x2CF`；半角片假名使用 `index=byte+0x2AD`。

双字节先转换为 JIS 行列，再按每行 94 个槽位排列：

```python
row = (lead - (0x71 if lead < 0xA0 else 0xB1)) * 2
trail -= (trail > 0x7F)
if trail > 0x9D:
    row += 2
    col = trail - 0x7D
else:
    row += 1
    col = trail - 0x1F
index = (row - 0x21) * 94 + col - 0x21
```

例如：`8140`→0（全角空格），`82A0`→283（あ），`889F`→1410（亜），`8ABF`→1818（漢），ASCII `41`→784（A）。

8192 槽的最后一个双字节形状为 `ECAC`。引擎识别的双字节首字节范围更大，因此“码形合法”不代表结果落在本文件的字库边界内。

## EBOOT 内的 Unicode 码表

地址 `0x810B8A54`，ELF 文件偏移 `0xB8174`，长度 0x20000，结束地址 `0x810D8A54`。
用 Unicode BMP 值直接索引 u16LE；表值按高、低字节输出成 Shift-JIS，`FFFF` 表示未映射。

原表有 9485 个非 FFFF 条目，其中 7232 个条目的字形索引落在本字库范围内。这个数字包含控制字符和多个 Unicode 到同一编码的别名，不能理解为 7232 个独立可见字形。
少数西文字符有降级映射，例如带语义区别的 Unicode 可落到普通拉丁字母；因此保存了完整原表，而非直接用系统 CP932 编码器代替游戏行为。

`game_code_table.tsv` 的主字符名来自 CP932，`eboot_unicode_aliases` 列则来自 EBOOT 原始表。未分配或自定义槽的 Unicode 名称仍需按实际字形确认。

## 剧情与系统文本

`sn.bin` 开头的 u32LE 是解压长度。其后采用 4096 字节零初始化环形缓冲，初始写指针 0xFEE；标志从低位开始，1 为原字节，0 为 12 位绝对偏移、长度低 4 位加 3 的回溯复制。
1548655 字节压缩数据被恰好消耗完，恢复 4886272 字节。

解压后开头为 173 个 16 字节目录条目：偏移、长度、两个保留字段。目录连续覆盖整个文件；每个条目已另存到 `04_日文原文/sn_entries/`。

文本中的 `%N` 等控制标记保留原样。0x45/46/47 的窗口值为默认值或 10 时还有一个消息 ID；窗口 13 的名字串通常没有该额外字段。选项记录含 10 字节元数据和 NUL 终止文本，跳转偏移相对于当前条目。

**覆盖范围：** 当前正文、人名及选项提取使用已核对字段布局的指令模式扫描，尚未对每条字节码建立完整控制流，因此不声称已穷尽所有剧情／UI 字符串。
另外保留了 [sn_string_candidates.tsv](../04_日文原文/sn_string_candidates.tsv) 和 [eboot_string_candidates.tsv](../04_日文原文/eboot_string_candidates.tsv) 作为查漏资料；候选表可能包含二进制数据误识别。
未落入正文／选项模式的可读串包括 AfterStory 解锁通知和路线标签，需继续补充对应指令后再纳入正式导入流程。

EBOOT 的大量日文文案实际是 UTF-8，经上述 Unicode 码表转码；直接按 CP932 解读会产生乱码。
EBOOT 中还保留了其他作品的人名、章节等引擎残留字符串，不能把全部候选串当作本作实际会显示的界面。

## 已完成的验证

- 零售 SELF 内的 SHA-256 摘要与解出的 ELF 完全相等。
- 字库 PNG 索引重新打包，加原头、调色板和尾部，逐字节恢复原 VTX。
- Unicorn 执行原始 Thumb 函数 0x8100D0B2，共 11438 组编码；与提取公式零差异。
- Unicorn 执行原始 Thumb 函数 0x8104DA28，4886272 个输出字节与 Python 解压结果完全相等。
- 文本记录保留原始偏移及字节；CP932 编码往返与导出记录一致。

机器码验证记录：[machine_code_verification.json](ghidra/machine_code_verification.json)。

## 复现

在项目根目录用 PowerShell 执行：

```powershell
python -m pip install -r 'Python工具/requirements_analysis.txt'
python 'Python工具/decrypt_game.py'
python 'Python工具/prepare_ghidra.py'
& './Python工具/run_ghidra.ps1'
& './Python工具/run_ghidra.ps1' -Annotate
python 'Python工具/extract_font_text.py'
python 'Python工具/extract_script_strings.py'
python 'Python工具/verify_machine_code.py'
```

工具位于 `tools/`，Ghidra 导出脚本在 `Python工具/ghidra_scripts/`。依赖的许可证和下载来源已保留。

## 参考资料

- 用户指定账号的 [PCSG00337 汉化工程](https://github.com/jingyueyueyueyue/PCSG00337-Chinese-Patch)：参考其 Ghidra 交叉引用／反编译导出方法，未套用另一游戏的地址、字体或码表。
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) 与 [VitaLoaderRedux](https://github.com/CreepNT/VitaLoaderRedux)。
- [psvpfstools](https://github.com/motoharu-gosuto/psvpfstools)、[Vita3K 原生 F00D 实现](https://github.com/Vita3K/psvpfsparser/blob/master/F00DNativeKeyEncryptor.cpp)。
- [psvdec](https://github.com/rreha/psvdec)：沿用本机现有 MIT 授权脚本进行 SELF 转换。

参考文件与指定仓库提交号保存在 `03_文件结构分析/references/`；工具发布版本、下载地址和 SHA-256 保存在 `tools/sources.json`。
