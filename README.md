# Starry☆Sky ～Spring Stories～ 简体中文汉化工程

适用于 PS Vita 日版 `PCSG00510`。工程包含剧情、人名、选项及 EBOOT 译文，另有提取、单字体字库重建、文本回填、打包及校验代码。

## 本地构建

1. 安装 Python 3.12. 在仓库根目录执行 `python -m pip install -r Python工具/requirements_analysis.txt`。
2. 将自己游戏的本地导出放在 `01_游戏文件/`。若输入仍处于 PFS 封装，请准备 [psvpfstools](https://github.com/motoharu-gosuto/psvpfstools) 的 Windows `psvpfsparser.exe` 及配套 DLL，放入 `tools/pfsparser/`。将 [psvdec](https://github.com/rreha/psvdec) 的 Python 文件放入 `tools/psvdec/`，再执行 `python -X utf8 Python工具/decrypt_game.py`。已有本地提取结果时，可以直接使用 `02_解包资源/PCSG00510_decrypted/` 下的 `PCSG00510.elf`、`eboot.bin`、`data/font32.vtx` 和 `data/sn.bin`。
3. 准备单一 Noto Sans SC Regular 字体。当前成品使用 Windows 下的 `Noto Sans SC (TrueType).otf`。字体在其他目录时，用 `--font` 指定路径。
4. 依次执行以下命令。

```powershell
python -X utf8 'Python工具/extract_font_text.py'
python -X utf8 'Python工具/extract_script_strings.py'
python -X utf8 'Python工具/import_chinese.py'
```

成品位于 `07_修改后的资源/PCSG00510/`，校验报告是同级的 `import_report.json`。备份 Vita3K 游戏目录后，将成品的 `eboot.bin`、`data/font32.vtx`、`data/sn.bin` 放到游戏目录中的对应位置，再重启游戏。

## 译表与分析

`05_AI翻译/` 的四张 TSV 使用 UTF-8，只保存译文及游戏内偏移。剧情与选项的源记录、EBOOT 原始字节、字库槽位表均由提取脚本在本机生成。译表中的剧情偏移已对齐至当前版本。EBOOT 两份译表保留交集，构建时按偏移核对并去重。

构建会读回 48,871 条剧情及人名、312 条选项和 354 条去重的 EBOOT 译文，并执行原游戏的解压与 EBOOT 转码例程校验。在 `06_中文字体/zh_cn/` 可查看本地生成的字库预览和码表。

字库格式、脚本指令及 Ghidra 使用方式见 [EBOOT 字库与码表分析](03_文件结构分析/EBOOT_字库与码表分析.md)。其中的相对文件路径指向本机生成的分析产物。
