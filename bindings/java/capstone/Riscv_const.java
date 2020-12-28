// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT
package capstone;

public class Riscv_const {

	// Operand type for instruction's operands

	public static final int RISCV_OP_INVALID = 0;
	public static final int RISCV_OP_REG = 1;
	public static final int RISCV_OP_IMM = 2;
	public static final int RISCV_OP_MEM = 3;

	// RISCV registers

	public static final int RISCV_REG_INVALID = 0;

	// General purpose registers
	public static final int RISCV_REG_X0 = 1;
	public static final int RISCV_REG_ZERO = RISCV_REG_X0;
	public static final int RISCV_REG_X1 = 2;
	public static final int RISCV_REG_RA = RISCV_REG_X1;
	public static final int RISCV_REG_X2 = 3;
	public static final int RISCV_REG_SP = RISCV_REG_X2;
	public static final int RISCV_REG_X3 = 4;
	public static final int RISCV_REG_GP = RISCV_REG_X3;
	public static final int RISCV_REG_X4 = 5;
	public static final int RISCV_REG_TP = RISCV_REG_X4;
	public static final int RISCV_REG_X5 = 6;
	public static final int RISCV_REG_T0 = RISCV_REG_X5;
	public static final int RISCV_REG_X6 = 7;
	public static final int RISCV_REG_T1 = RISCV_REG_X6;
	public static final int RISCV_REG_X7 = 8;
	public static final int RISCV_REG_T2 = RISCV_REG_X7;
	public static final int RISCV_REG_X8 = 9;
	public static final int RISCV_REG_S0 = RISCV_REG_X8;
	public static final int RISCV_REG_FP = RISCV_REG_X8;
	public static final int RISCV_REG_X9 = 10;
	public static final int RISCV_REG_S1 = RISCV_REG_X9;
	public static final int RISCV_REG_X10 = 11;
	public static final int RISCV_REG_A0 = RISCV_REG_X10;
	public static final int RISCV_REG_X11 = 12;
	public static final int RISCV_REG_A1 = RISCV_REG_X11;
	public static final int RISCV_REG_X12 = 13;
	public static final int RISCV_REG_A2 = RISCV_REG_X12;
	public static final int RISCV_REG_X13 = 14;
	public static final int RISCV_REG_A3 = RISCV_REG_X13;
	public static final int RISCV_REG_X14 = 15;
	public static final int RISCV_REG_A4 = RISCV_REG_X14;
	public static final int RISCV_REG_X15 = 16;
	public static final int RISCV_REG_A5 = RISCV_REG_X15;
	public static final int RISCV_REG_X16 = 17;
	public static final int RISCV_REG_A6 = RISCV_REG_X16;
	public static final int RISCV_REG_X17 = 18;
	public static final int RISCV_REG_A7 = RISCV_REG_X17;
	public static final int RISCV_REG_X18 = 19;
	public static final int RISCV_REG_S2 = RISCV_REG_X18;
	public static final int RISCV_REG_X19 = 20;
	public static final int RISCV_REG_S3 = RISCV_REG_X19;
	public static final int RISCV_REG_X20 = 21;
	public static final int RISCV_REG_S4 = RISCV_REG_X20;
	public static final int RISCV_REG_X21 = 22;
	public static final int RISCV_REG_S5 = RISCV_REG_X21;
	public static final int RISCV_REG_X22 = 23;
	public static final int RISCV_REG_S6 = RISCV_REG_X22;
	public static final int RISCV_REG_X23 = 24;
	public static final int RISCV_REG_S7 = RISCV_REG_X23;
	public static final int RISCV_REG_X24 = 25;
	public static final int RISCV_REG_S8 = RISCV_REG_X24;
	public static final int RISCV_REG_X25 = 26;
	public static final int RISCV_REG_S9 = RISCV_REG_X25;
	public static final int RISCV_REG_X26 = 27;
	public static final int RISCV_REG_S10 = RISCV_REG_X26;
	public static final int RISCV_REG_X27 = 28;
	public static final int RISCV_REG_S11 = RISCV_REG_X27;
	public static final int RISCV_REG_X28 = 29;
	public static final int RISCV_REG_T3 = RISCV_REG_X28;
	public static final int RISCV_REG_X29 = 30;
	public static final int RISCV_REG_T4 = RISCV_REG_X29;
	public static final int RISCV_REG_X30 = 31;
	public static final int RISCV_REG_T5 = RISCV_REG_X30;
	public static final int RISCV_REG_X31 = 32;
	public static final int RISCV_REG_T6 = RISCV_REG_X31;

	// Floating-point registers
	public static final int RISCV_REG_F0_32 = 33;
	public static final int RISCV_REG_F0_64 = 34;
	public static final int RISCV_REG_F1_32 = 35;
	public static final int RISCV_REG_F1_64 = 36;
	public static final int RISCV_REG_F2_32 = 37;
	public static final int RISCV_REG_F2_64 = 38;
	public static final int RISCV_REG_F3_32 = 39;
	public static final int RISCV_REG_F3_64 = 40;
	public static final int RISCV_REG_F4_32 = 41;
	public static final int RISCV_REG_F4_64 = 42;
	public static final int RISCV_REG_F5_32 = 43;
	public static final int RISCV_REG_F5_64 = 44;
	public static final int RISCV_REG_F6_32 = 45;
	public static final int RISCV_REG_F6_64 = 46;
	public static final int RISCV_REG_F7_32 = 47;
	public static final int RISCV_REG_F7_64 = 48;
	public static final int RISCV_REG_F8_32 = 49;
	public static final int RISCV_REG_F8_64 = 50;
	public static final int RISCV_REG_F9_32 = 51;
	public static final int RISCV_REG_F9_64 = 52;
	public static final int RISCV_REG_F10_32 = 53;
	public static final int RISCV_REG_F10_64 = 54;
	public static final int RISCV_REG_F11_32 = 55;
	public static final int RISCV_REG_F11_64 = 56;
	public static final int RISCV_REG_F12_32 = 57;
	public static final int RISCV_REG_F12_64 = 58;
	public static final int RISCV_REG_F13_32 = 59;
	public static final int RISCV_REG_F13_64 = 60;
	public static final int RISCV_REG_F14_32 = 61;
	public static final int RISCV_REG_F14_64 = 62;
	public static final int RISCV_REG_F15_32 = 63;
	public static final int RISCV_REG_F15_64 = 64;
	public static final int RISCV_REG_F16_32 = 65;
	public static final int RISCV_REG_F16_64 = 66;
	public static final int RISCV_REG_F17_32 = 67;
	public static final int RISCV_REG_F17_64 = 68;
	public static final int RISCV_REG_F18_32 = 69;
	public static final int RISCV_REG_F18_64 = 70;
	public static final int RISCV_REG_F19_32 = 71;
	public static final int RISCV_REG_F19_64 = 72;
	public static final int RISCV_REG_F20_32 = 73;
	public static final int RISCV_REG_F20_64 = 74;
	public static final int RISCV_REG_F21_32 = 75;
	public static final int RISCV_REG_F21_64 = 76;
	public static final int RISCV_REG_F22_32 = 77;
	public static final int RISCV_REG_F22_64 = 78;
	public static final int RISCV_REG_F23_32 = 79;
	public static final int RISCV_REG_F23_64 = 80;
	public static final int RISCV_REG_F24_32 = 81;
	public static final int RISCV_REG_F24_64 = 82;
	public static final int RISCV_REG_F25_32 = 83;
	public static final int RISCV_REG_F25_64 = 84;
	public static final int RISCV_REG_F26_32 = 85;
	public static final int RISCV_REG_F26_64 = 86;
	public static final int RISCV_REG_F27_32 = 87;
	public static final int RISCV_REG_F27_64 = 88;
	public static final int RISCV_REG_F28_32 = 89;
	public static final int RISCV_REG_F28_64 = 90;
	public static final int RISCV_REG_F29_32 = 91;
	public static final int RISCV_REG_F29_64 = 92;
	public static final int RISCV_REG_F30_32 = 93;
	public static final int RISCV_REG_F30_64 = 94;
	public static final int RISCV_REG_F31_32 = 95;
	public static final int RISCV_REG_F31_64 = 96;
	public static final int RISCV_REG_ENDING = 97;

	// RISCV instruction

	public static final int RISCV_INS_INVALID = 0;
	public static final int RISCV_INS_ADD = 1;
	public static final int RISCV_INS_ADDI = 2;
	public static final int RISCV_INS_ADDIW = 3;
	public static final int RISCV_INS_ADDW = 4;
	public static final int RISCV_INS_AMOADD_D = 5;
	public static final int RISCV_INS_AMOADD_D_AQ = 6;
	public static final int RISCV_INS_AMOADD_D_AQ_RL = 7;
	public static final int RISCV_INS_AMOADD_D_RL = 8;
	public static final int RISCV_INS_AMOADD_W = 9;
	public static final int RISCV_INS_AMOADD_W_AQ = 10;
	public static final int RISCV_INS_AMOADD_W_AQ_RL = 11;
	public static final int RISCV_INS_AMOADD_W_RL = 12;
	public static final int RISCV_INS_AMOAND_D = 13;
	public static final int RISCV_INS_AMOAND_D_AQ = 14;
	public static final int RISCV_INS_AMOAND_D_AQ_RL = 15;
	public static final int RISCV_INS_AMOAND_D_RL = 16;
	public static final int RISCV_INS_AMOAND_W = 17;
	public static final int RISCV_INS_AMOAND_W_AQ = 18;
	public static final int RISCV_INS_AMOAND_W_AQ_RL = 19;
	public static final int RISCV_INS_AMOAND_W_RL = 20;
	public static final int RISCV_INS_AMOMAXU_D = 21;
	public static final int RISCV_INS_AMOMAXU_D_AQ = 22;
	public static final int RISCV_INS_AMOMAXU_D_AQ_RL = 23;
	public static final int RISCV_INS_AMOMAXU_D_RL = 24;
	public static final int RISCV_INS_AMOMAXU_W = 25;
	public static final int RISCV_INS_AMOMAXU_W_AQ = 26;
	public static final int RISCV_INS_AMOMAXU_W_AQ_RL = 27;
	public static final int RISCV_INS_AMOMAXU_W_RL = 28;
	public static final int RISCV_INS_AMOMAX_D = 29;
	public static final int RISCV_INS_AMOMAX_D_AQ = 30;
	public static final int RISCV_INS_AMOMAX_D_AQ_RL = 31;
	public static final int RISCV_INS_AMOMAX_D_RL = 32;
	public static final int RISCV_INS_AMOMAX_W = 33;
	public static final int RISCV_INS_AMOMAX_W_AQ = 34;
	public static final int RISCV_INS_AMOMAX_W_AQ_RL = 35;
	public static final int RISCV_INS_AMOMAX_W_RL = 36;
	public static final int RISCV_INS_AMOMINU_D = 37;
	public static final int RISCV_INS_AMOMINU_D_AQ = 38;
	public static final int RISCV_INS_AMOMINU_D_AQ_RL = 39;
	public static final int RISCV_INS_AMOMINU_D_RL = 40;
	public static final int RISCV_INS_AMOMINU_W = 41;
	public static final int RISCV_INS_AMOMINU_W_AQ = 42;
	public static final int RISCV_INS_AMOMINU_W_AQ_RL = 43;
	public static final int RISCV_INS_AMOMINU_W_RL = 44;
	public static final int RISCV_INS_AMOMIN_D = 45;
	public static final int RISCV_INS_AMOMIN_D_AQ = 46;
	public static final int RISCV_INS_AMOMIN_D_AQ_RL = 47;
	public static final int RISCV_INS_AMOMIN_D_RL = 48;
	public static final int RISCV_INS_AMOMIN_W = 49;
	public static final int RISCV_INS_AMOMIN_W_AQ = 50;
	public static final int RISCV_INS_AMOMIN_W_AQ_RL = 51;
	public static final int RISCV_INS_AMOMIN_W_RL = 52;
	public static final int RISCV_INS_AMOOR_D = 53;
	public static final int RISCV_INS_AMOOR_D_AQ = 54;
	public static final int RISCV_INS_AMOOR_D_AQ_RL = 55;
	public static final int RISCV_INS_AMOOR_D_RL = 56;
	public static final int RISCV_INS_AMOOR_W = 57;
	public static final int RISCV_INS_AMOOR_W_AQ = 58;
	public static final int RISCV_INS_AMOOR_W_AQ_RL = 59;
	public static final int RISCV_INS_AMOOR_W_RL = 60;
	public static final int RISCV_INS_AMOSWAP_D = 61;
	public static final int RISCV_INS_AMOSWAP_D_AQ = 62;
	public static final int RISCV_INS_AMOSWAP_D_AQ_RL = 63;
	public static final int RISCV_INS_AMOSWAP_D_RL = 64;
	public static final int RISCV_INS_AMOSWAP_W = 65;
	public static final int RISCV_INS_AMOSWAP_W_AQ = 66;
	public static final int RISCV_INS_AMOSWAP_W_AQ_RL = 67;
	public static final int RISCV_INS_AMOSWAP_W_RL = 68;
	public static final int RISCV_INS_AMOXOR_D = 69;
	public static final int RISCV_INS_AMOXOR_D_AQ = 70;
	public static final int RISCV_INS_AMOXOR_D_AQ_RL = 71;
	public static final int RISCV_INS_AMOXOR_D_RL = 72;
	public static final int RISCV_INS_AMOXOR_W = 73;
	public static final int RISCV_INS_AMOXOR_W_AQ = 74;
	public static final int RISCV_INS_AMOXOR_W_AQ_RL = 75;
	public static final int RISCV_INS_AMOXOR_W_RL = 76;
	public static final int RISCV_INS_AND = 77;
	public static final int RISCV_INS_ANDI = 78;
	public static final int RISCV_INS_AUIPC = 79;
	public static final int RISCV_INS_BEQ = 80;
	public static final int RISCV_INS_BGE = 81;
	public static final int RISCV_INS_BGEU = 82;
	public static final int RISCV_INS_BLT = 83;
	public static final int RISCV_INS_BLTU = 84;
	public static final int RISCV_INS_BNE = 85;
	public static final int RISCV_INS_CSRRC = 86;
	public static final int RISCV_INS_CSRRCI = 87;
	public static final int RISCV_INS_CSRRS = 88;
	public static final int RISCV_INS_CSRRSI = 89;
	public static final int RISCV_INS_CSRRW = 90;
	public static final int RISCV_INS_CSRRWI = 91;
	public static final int RISCV_INS_C_ADD = 92;
	public static final int RISCV_INS_C_ADDI = 93;
	public static final int RISCV_INS_C_ADDI16SP = 94;
	public static final int RISCV_INS_C_ADDI4SPN = 95;
	public static final int RISCV_INS_C_ADDIW = 96;
	public static final int RISCV_INS_C_ADDW = 97;
	public static final int RISCV_INS_C_AND = 98;
	public static final int RISCV_INS_C_ANDI = 99;
	public static final int RISCV_INS_C_BEQZ = 100;
	public static final int RISCV_INS_C_BNEZ = 101;
	public static final int RISCV_INS_C_EBREAK = 102;
	public static final int RISCV_INS_C_FLD = 103;
	public static final int RISCV_INS_C_FLDSP = 104;
	public static final int RISCV_INS_C_FLW = 105;
	public static final int RISCV_INS_C_FLWSP = 106;
	public static final int RISCV_INS_C_FSD = 107;
	public static final int RISCV_INS_C_FSDSP = 108;
	public static final int RISCV_INS_C_FSW = 109;
	public static final int RISCV_INS_C_FSWSP = 110;
	public static final int RISCV_INS_C_J = 111;
	public static final int RISCV_INS_C_JAL = 112;
	public static final int RISCV_INS_C_JALR = 113;
	public static final int RISCV_INS_C_JR = 114;
	public static final int RISCV_INS_C_LD = 115;
	public static final int RISCV_INS_C_LDSP = 116;
	public static final int RISCV_INS_C_LI = 117;
	public static final int RISCV_INS_C_LUI = 118;
	public static final int RISCV_INS_C_LW = 119;
	public static final int RISCV_INS_C_LWSP = 120;
	public static final int RISCV_INS_C_MV = 121;
	public static final int RISCV_INS_C_NOP = 122;
	public static final int RISCV_INS_C_OR = 123;
	public static final int RISCV_INS_C_SD = 124;
	public static final int RISCV_INS_C_SDSP = 125;
	public static final int RISCV_INS_C_SLLI = 126;
	public static final int RISCV_INS_C_SRAI = 127;
	public static final int RISCV_INS_C_SRLI = 128;
	public static final int RISCV_INS_C_SUB = 129;
	public static final int RISCV_INS_C_SUBW = 130;
	public static final int RISCV_INS_C_SW = 131;
	public static final int RISCV_INS_C_SWSP = 132;
	public static final int RISCV_INS_C_UNIMP = 133;
	public static final int RISCV_INS_C_XOR = 134;
	public static final int RISCV_INS_DIV = 135;
	public static final int RISCV_INS_DIVU = 136;
	public static final int RISCV_INS_DIVUW = 137;
	public static final int RISCV_INS_DIVW = 138;
	public static final int RISCV_INS_EBREAK = 139;
	public static final int RISCV_INS_ECALL = 140;
	public static final int RISCV_INS_FADD_D = 141;
	public static final int RISCV_INS_FADD_S = 142;
	public static final int RISCV_INS_FCLASS_D = 143;
	public static final int RISCV_INS_FCLASS_S = 144;
	public static final int RISCV_INS_FCVT_D_L = 145;
	public static final int RISCV_INS_FCVT_D_LU = 146;
	public static final int RISCV_INS_FCVT_D_S = 147;
	public static final int RISCV_INS_FCVT_D_W = 148;
	public static final int RISCV_INS_FCVT_D_WU = 149;
	public static final int RISCV_INS_FCVT_LU_D = 150;
	public static final int RISCV_INS_FCVT_LU_S = 151;
	public static final int RISCV_INS_FCVT_L_D = 152;
	public static final int RISCV_INS_FCVT_L_S = 153;
	public static final int RISCV_INS_FCVT_S_D = 154;
	public static final int RISCV_INS_FCVT_S_L = 155;
	public static final int RISCV_INS_FCVT_S_LU = 156;
	public static final int RISCV_INS_FCVT_S_W = 157;
	public static final int RISCV_INS_FCVT_S_WU = 158;
	public static final int RISCV_INS_FCVT_WU_D = 159;
	public static final int RISCV_INS_FCVT_WU_S = 160;
	public static final int RISCV_INS_FCVT_W_D = 161;
	public static final int RISCV_INS_FCVT_W_S = 162;
	public static final int RISCV_INS_FDIV_D = 163;
	public static final int RISCV_INS_FDIV_S = 164;
	public static final int RISCV_INS_FENCE = 165;
	public static final int RISCV_INS_FENCE_I = 166;
	public static final int RISCV_INS_FENCE_TSO = 167;
	public static final int RISCV_INS_FEQ_D = 168;
	public static final int RISCV_INS_FEQ_S = 169;
	public static final int RISCV_INS_FLD = 170;
	public static final int RISCV_INS_FLE_D = 171;
	public static final int RISCV_INS_FLE_S = 172;
	public static final int RISCV_INS_FLT_D = 173;
	public static final int RISCV_INS_FLT_S = 174;
	public static final int RISCV_INS_FLW = 175;
	public static final int RISCV_INS_FMADD_D = 176;
	public static final int RISCV_INS_FMADD_S = 177;
	public static final int RISCV_INS_FMAX_D = 178;
	public static final int RISCV_INS_FMAX_S = 179;
	public static final int RISCV_INS_FMIN_D = 180;
	public static final int RISCV_INS_FMIN_S = 181;
	public static final int RISCV_INS_FMSUB_D = 182;
	public static final int RISCV_INS_FMSUB_S = 183;
	public static final int RISCV_INS_FMUL_D = 184;
	public static final int RISCV_INS_FMUL_S = 185;
	public static final int RISCV_INS_FMV_D_X = 186;
	public static final int RISCV_INS_FMV_W_X = 187;
	public static final int RISCV_INS_FMV_X_D = 188;
	public static final int RISCV_INS_FMV_X_W = 189;
	public static final int RISCV_INS_FNMADD_D = 190;
	public static final int RISCV_INS_FNMADD_S = 191;
	public static final int RISCV_INS_FNMSUB_D = 192;
	public static final int RISCV_INS_FNMSUB_S = 193;
	public static final int RISCV_INS_FSD = 194;
	public static final int RISCV_INS_FSGNJN_D = 195;
	public static final int RISCV_INS_FSGNJN_S = 196;
	public static final int RISCV_INS_FSGNJX_D = 197;
	public static final int RISCV_INS_FSGNJX_S = 198;
	public static final int RISCV_INS_FSGNJ_D = 199;
	public static final int RISCV_INS_FSGNJ_S = 200;
	public static final int RISCV_INS_FSQRT_D = 201;
	public static final int RISCV_INS_FSQRT_S = 202;
	public static final int RISCV_INS_FSUB_D = 203;
	public static final int RISCV_INS_FSUB_S = 204;
	public static final int RISCV_INS_FSW = 205;
	public static final int RISCV_INS_JAL = 206;
	public static final int RISCV_INS_JALR = 207;
	public static final int RISCV_INS_LB = 208;
	public static final int RISCV_INS_LBU = 209;
	public static final int RISCV_INS_LD = 210;
	public static final int RISCV_INS_LH = 211;
	public static final int RISCV_INS_LHU = 212;
	public static final int RISCV_INS_LR_D = 213;
	public static final int RISCV_INS_LR_D_AQ = 214;
	public static final int RISCV_INS_LR_D_AQ_RL = 215;
	public static final int RISCV_INS_LR_D_RL = 216;
	public static final int RISCV_INS_LR_W = 217;
	public static final int RISCV_INS_LR_W_AQ = 218;
	public static final int RISCV_INS_LR_W_AQ_RL = 219;
	public static final int RISCV_INS_LR_W_RL = 220;
	public static final int RISCV_INS_LUI = 221;
	public static final int RISCV_INS_LW = 222;
	public static final int RISCV_INS_LWU = 223;
	public static final int RISCV_INS_MRET = 224;
	public static final int RISCV_INS_MUL = 225;
	public static final int RISCV_INS_MULH = 226;
	public static final int RISCV_INS_MULHSU = 227;
	public static final int RISCV_INS_MULHU = 228;
	public static final int RISCV_INS_MULW = 229;
	public static final int RISCV_INS_OR = 230;
	public static final int RISCV_INS_ORI = 231;
	public static final int RISCV_INS_REM = 232;
	public static final int RISCV_INS_REMU = 233;
	public static final int RISCV_INS_REMUW = 234;
	public static final int RISCV_INS_REMW = 235;
	public static final int RISCV_INS_SB = 236;
	public static final int RISCV_INS_SC_D = 237;
	public static final int RISCV_INS_SC_D_AQ = 238;
	public static final int RISCV_INS_SC_D_AQ_RL = 239;
	public static final int RISCV_INS_SC_D_RL = 240;
	public static final int RISCV_INS_SC_W = 241;
	public static final int RISCV_INS_SC_W_AQ = 242;
	public static final int RISCV_INS_SC_W_AQ_RL = 243;
	public static final int RISCV_INS_SC_W_RL = 244;
	public static final int RISCV_INS_SD = 245;
	public static final int RISCV_INS_SFENCE_VMA = 246;
	public static final int RISCV_INS_SH = 247;
	public static final int RISCV_INS_SLL = 248;
	public static final int RISCV_INS_SLLI = 249;
	public static final int RISCV_INS_SLLIW = 250;
	public static final int RISCV_INS_SLLW = 251;
	public static final int RISCV_INS_SLT = 252;
	public static final int RISCV_INS_SLTI = 253;
	public static final int RISCV_INS_SLTIU = 254;
	public static final int RISCV_INS_SLTU = 255;
	public static final int RISCV_INS_SRA = 256;
	public static final int RISCV_INS_SRAI = 257;
	public static final int RISCV_INS_SRAIW = 258;
	public static final int RISCV_INS_SRAW = 259;
	public static final int RISCV_INS_SRET = 260;
	public static final int RISCV_INS_SRL = 261;
	public static final int RISCV_INS_SRLI = 262;
	public static final int RISCV_INS_SRLIW = 263;
	public static final int RISCV_INS_SRLW = 264;
	public static final int RISCV_INS_SUB = 265;
	public static final int RISCV_INS_SUBW = 266;
	public static final int RISCV_INS_SW = 267;
	public static final int RISCV_INS_UNIMP = 268;
	public static final int RISCV_INS_URET = 269;
	public static final int RISCV_INS_WFI = 270;
	public static final int RISCV_INS_XOR = 271;
	public static final int RISCV_INS_XORI = 272;
	public static final int RISCV_INS_ENDING = 273;

	// Group of RISCV instructions

	public static final int RISCV_GRP_INVALID = 0;
	public static final int RISCV_GRP_JUMP = 1;
	public static final int RISCV_GRP_ISRV32 = 128;
	public static final int RISCV_GRP_ISRV64 = 129;
	public static final int RISCV_GRP_HASSTDEXTA = 130;
	public static final int RISCV_GRP_HASSTDEXTC = 131;
	public static final int RISCV_GRP_HASSTDEXTD = 132;
	public static final int RISCV_GRP_HASSTDEXTF = 133;
	public static final int RISCV_GRP_HASSTDEXTM = 134;
	public static final int RISCV_GRP_ISRVA = 135;
	public static final int RISCV_GRP_ISRVC = 136;
	public static final int RISCV_GRP_ISRVD = 137;
	public static final int RISCV_GRP_ISRVCD = 138;
	public static final int RISCV_GRP_ISRVF = 139;
	public static final int RISCV_GRP_ISRV32C = 140;
	public static final int RISCV_GRP_ISRV32CF = 141;
	public static final int RISCV_GRP_ISRVM = 142;
	public static final int RISCV_GRP_ISRV64A = 143;
	public static final int RISCV_GRP_ISRV64C = 144;
	public static final int RISCV_GRP_ISRV64D = 145;
	public static final int RISCV_GRP_ISRV64F = 146;
	public static final int RISCV_GRP_ISRV64M = 147;
	public static final int RISCV_GRP_ENDING = 148;
}