// Capstone Java binding

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Riscv_const.*;

public class Riscv {

  public static class MemType extends Structure {
    public int base;
    public long disp;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("base", "disp");
    }
  }

  public static class OpValue extends Union {
    public int reg;
    public long imm;
    public Riscv.MemType mem;

    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "mem");
    }
  }

  public static class Operand extends Structure {
    public int type;
    public Riscv.OpValue value;

    public void read() {
      super.read();
      if (type == RISCV_OP_MEM)
        value.setType(Riscv.MemType.class);
      if (type == RISCV_OP_IMM)
        value.setType(Long.TYPE);
      if (type == RISCV_OP_REG)
        value.setType(Integer.TYPE);
      if (type == RISCV_OP_INVALID)
        return;
      readField("value");
    }
    @Override
    public List getFieldOrder() {
      return Arrays.asList("type", "value");
    }
  }

  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte need_effective_addr;
    public byte op_count;
    public Riscv.Operand[] op;

    public UnionOpInfo() {
      op = new Riscv.Operand[8];
    }

    public void read() {
      readField("need_effective_addr");
      readField("op_count");
      op = new Riscv.Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("need_effective_addr", "op_count", "op");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public byte needEffectiveAddr;
    public Riscv.Operand[] op;

    public OpInfo(Riscv.UnionOpInfo e) {
      needEffectiveAddr = e.need_effective_addr;
      op = e.op;
    }
  }
}
