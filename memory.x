MEMORY
{
    FLASH    : ORIGIN = 0x08000000, LENGTH = 128K /* BANK_1 */
    QSPI_FLASH : ORIGIN = 0x90000000, LENGTH = 8M
    DTCM  : ORIGIN = 0x20000000, LENGTH = 128K  /* DTCM RAM */
    RAM   : ORIGIN = 0x24000000, LENGTH = 512K  /* AXI SRAM */
    ITCM  : ORIGIN = 0x00000000, LENGTH = 64K   /* ITCM RAM */
}

__bootloader_code_start = ORIGIN(FLASH);
__bootloader_code_end   = __bootloader_code_start + 128K;

/* QSPI Flash ：
   - Active：4M - 4K
   - DFU：4M
   - Bootloader：4K
*/
__bootloader_active_start = ORIGIN(QSPI_FLASH);
__bootloader_active_end   = __bootloader_active_start + (4M - 4K);

__bootloader_dfu_start    = __bootloader_active_end;
__bootloader_dfu_end      = __bootloader_dfu_start + 4M;

__bootloader_state_start  = __bootloader_dfu_end;
__bootloader_state_end    = __bootloader_state_start + 4K;
