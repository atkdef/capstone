// Capstone Java binding

import capstone.Capstone;
import capstone.Riscv;

import static capstone.Riscv_const.*;

public class TestRiscv {

  static byte[] hexString2Byte(String s) {
    // from http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
              + Character.digit(s.charAt(i+1), 16));
    }
    return data;
  }

  static final String RISCV_CODE32 = "3734000097820000ef008000eff01fffe7004500e700c0ff63054100e39d61fe63ca93006353b5006365d6006376f700038818000399490003aa6a0003cb2b0103dc8c012386ad03239ace03238fef019300e00013a1010113b2027d13c303dd13e4c41213f5850c1396e60113d7970113d8f84033894901b30a7b4133acac01b33dde0133d26240b343940033e5c500b376f700b3543901b3503100339f0f00";
  static final String RISCV_CODE64 = "1304a87a";

  public static Capstone cs;

  private static String hex(int i) {
    return Integer.toString(i, 16);
  }

  private static String hex(long i) {
    return Long.toString(i, 16);
  }

  public static void print_ins_detail(Capstone.CsInsn ins) {
    System.out.printf("0x%x:\t%s\t%s\n", ins.address, ins.mnemonic, ins.opStr);

    if (ins.id == 0)
      return;

    Riscv.OpInfo operands = (Riscv.OpInfo) ins.operands;

    System.out.printf("\tneed_effective_address: %d\n", ((Riscv.OpInfo) ins.operands).needEffectiveAddr);

    if (operands.op.length != 0) {
      System.out.printf("\top_count: %d\n", operands.op.length);
      for (int c=0; c<operands.op.length; c++) {
        Riscv.Operand i = (Riscv.Operand) operands.op[c];
        String imm = hex(i.value.imm);
        if (i.type == RISCV_OP_REG)
          System.out.printf("\t\toperands[%d].type: REG = %s\n", c, ins.regName(i.value.reg));
        if (i.type == RISCV_OP_IMM)
          System.out.printf("\t\toperands[%d].type: IMM = 0x%x\n", c, i.value.imm);
        if (i.type == RISCV_OP_MEM) {
          System.out.printf("\t\toperands[%d].type: MEM\n", c);
          String base = ins.regName(i.value.mem.base);
          if (base != null)
            System.out.printf("\t\t\toperands[%d].mem.base: REG = %s\n", c, base);
          if (i.value.mem.disp != 0)
            System.out.printf("\t\t\toperands[%d].mem.disp: %s\n", c, hex(i.value.mem.disp));
        }
      }
    }
  }

  public static void main(String argv[]) {

    final TestBasic.platform[] all_tests = {
            new TestBasic.platform(Capstone.CS_ARCH_RISCV, Capstone.CS_MODE_RISCV32, hexString2Byte(RISCV_CODE32), "RISCV-32"),
            new TestBasic.platform(Capstone.CS_ARCH_RISCV, Capstone.CS_MODE_RISCV64, hexString2Byte(RISCV_CODE64), "RISCV-64"),
    };

    for (int i=0; i<all_tests.length; i++) {
      TestBasic.platform test = all_tests[i];
      System.out.println(new String(new char[16]).replace("\0", "*"));
      System.out.println("Platform: " + test.comment);
      System.out.println("Code: " + TestBasic.stringToHex(test.code));
      System.out.println("Disasm:");

      cs = new Capstone(test.arch, test.mode);
      cs.setDetail(Capstone.CS_OPT_ON);
      Capstone.CsInsn[] all_ins = cs.disasm(test.code, 0x1000);

      for (int j = 0; j < all_ins.length; j++) {
        print_ins_detail(all_ins[j]);
        System.out.println();
      }

      System.out.printf("0x%x:\n\n", all_ins[all_ins.length-1].address + all_ins[all_ins.length-1].size);

      // Close when done
      cs.close();
    }
  }
}
