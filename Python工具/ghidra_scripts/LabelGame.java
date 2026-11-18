// Apply evidence-backed names and comments, then export focused decompilation.
// @category StarrySky
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class LabelGame extends GhidraScript {
    public void run() throws Exception {
        File root = new File(getScriptArgs()[0]); root.mkdirs();
        String[][] targets = {
            {"8100cbb4", "SS_LoadFontAtlas", "Loads font32.vtx using the generic VTX loader. Font handle DAT_81116EC4."},
            {"8100d0b2", "SS_QueueShiftJisGlyph", "Character-to-glyph mapping verified with 11438 original Thumb executions, zero mismatches. ASCII slot=c+0x2CF; halfwidth slot=c+0x2AD; double-byte slot=JIS row-major 94 columns. Text pointer is ARM R0; first two decompiler parameters represent VFP arguments."},
            {"8100dca8", "SS_DrawShiftJisGlyph", "Uses the same Shift-JIS/JIS94 character-to-slot formula as SS_QueueShiftJisGlyph."},
            {"8100dfb8", "SS_DrawShiftJisGlyphAtPosition", "Uses the same Shift-JIS/JIS94 character-to-slot formula; submits glyph draw command."},
            {"8100d6ce", "SS_DecodeUtf8BmpCharacter", "Decodes one UTF-8 character into a 16-bit Unicode value (BMP). Called by SS_Utf8OrSjisToGameEncoding."},
            {"8100d77e", "SS_Utf8OrSjisToGameEncoding", "Converts UTF-8 using a 65536-entry u16LE Unicode-to-Shift-JIS LUT at 0x810B8A54 (ELF offset 0xB8174); 0xFFFF means unmapped. Existing SJIS bytes may pass through. LUT ends at 0x810D8A54."},
            {"8100d8ac", "SS_ConvertTextViaTemporaryBuffer", "Allocates 0x1000-byte temporary buffer and calls SS_Utf8OrSjisToGameEncoding; explains UTF-8 strings in EBOOT versus CP932 in scenario data."},
            {"81015b8a", "SS_LoadVtxOrXtxTexture", "Dispatches magic vtx to SS_LoadVtxTexture at 0x810158F4; handles xtx through a separate format switch. Do not confuse XTX case7 with this game's VTX kind0."},
            {"810158f4", "SS_LoadVtxTexture", "VTX kind byte +4=0: palette +0x20 size0x40, P4 pixels +0x60 size width*height/2, then (width>>5)*(height>>5) per-cell bytes. Endian byte+5=1 means little-endian header. font32.vtx is 2048x4096 with 8192 cells."},
            {"81017192", "SS_RenderFontGlyphQuad", "Glyph UV coordinates: x=(glyph%64)*32, y=(glyph/64)*32; normalized by 2048 and 4096. Confirms 64 columns of 32x32 cells."},
            {"8104da28", "SS_DecompressLzss", "u32LE output size, 4096-byte zero ring, initial cursor 0xFEE, LSB flags (1=literal), 12-bit absolute match offset, 4-bit length+3. Python extraction matched all 4886272 output bytes in original Thumb emulation."},
            {"81014d50", "SS_StartupAndLoadScenario", "References sn.bin and invokes SS_DecompressLzss to DAT_83D6D6A4."},
            {"8102c956", "SS_ReplayVmUntilCommandCounter", "Bytecode opcode dispatch via function-pointer table at 0x810B877C. Replay loop until saved command counter."},
            {"810307b2", "SS_VmText45", "Opcode 0x45: u16 window; extra u16 message ID for default(-1)/window10; NUL-terminated CP932 string, preserving percent control tokens."},
            {"8103192a", "SS_VmText46", "Opcode 0x46: same window/optional message ID/string layout; used for speaker labels with window13."},
            {"81032962", "SS_VmText47", "Opcode 0x47: same window/optional message ID/string layout; alternate aligned text rendering."},
            {"81029480", "SS_VmChoice31", "Opcode 0x31: three u16 header fields, then count records of 10-byte metadata plus NUL string; branch target is relative to current script chunk."},
            {"81029ede", "SS_VmChoice32", "Opcode 0x32: choice record layout matches 0x31; replay variant."}
        };
        DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
        try (PrintWriter idx = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(root,"key_functions.tsv")),StandardCharsets.UTF_8))) {
            idx.println("address\tname\tstatus\tevidence");
            for (String[] t : targets) {
                Function f = getFunctionAt(toAddr(t[0]));
                if (f == null) { idx.println(t[0]+"\t"+t[1]+"\tmissing\t"+t[2]); continue; }
                f.setName(t[1], SourceType.USER_DEFINED);
                f.setComment(t[2]);
                DecompileResults r = di.decompileFunction(f,60,monitor);
                String c = "// Address 0x"+t[0]+"\n// "+t[2]+"\n"+(r.decompileCompleted()?r.getDecompiledFunction().getC():"// FAILED "+r.getErrorMessage());
                Files.writeString(new File(root,t[0]+"_"+t[1]+".c").toPath(),c,StandardCharsets.UTF_8);
                idx.println(t[0]+"\t"+t[1]+"\t"+r.decompileCompleted()+"\t"+t[2]);
            }
        } finally { di.dispose(); }
        try(PrintWriter out = new PrintWriter(new File(root,"resource_xrefs.tsv"),StandardCharsets.UTF_8)) {
            out.println("resource_address\tfrom\tfunction");
            for(String address:new String[]{"8109d944","8109fdb4"}) {
                for(Reference r:currentProgram.getReferenceManager().getReferencesTo(toAddr(address))) {
                    Function f=getFunctionContaining(r.getFromAddress());
                    out.println(address+"\t"+r.getFromAddress()+"\t"+(f==null?"":f.getName()));
                }
            }
        }
        println("Annotated and exported "+targets.length+" key functions");
    }
}
