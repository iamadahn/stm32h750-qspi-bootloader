#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::Timer;
use embassy_stm32::Config;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::time::Hertz;
use embassy_stm32::mode::Blocking;
use embassy_stm32::qspi::{
    Instance, Qspi, TransferConfig,
};
use embassy_stm32::qspi::enums::{
    AddressSize, ChipSelectHighTime, DummyCycles, FIFOThresholdLevel, MemorySize, QspiWidth,
};
use {defmt_rtt as _, panic_probe as _};

#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    info!("Starting bootloader.");

    info!("Initialising clocks.");
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hsi = Some(HSIPrescaler::DIV1);
        config.rcc.csi = true;
        config.rcc.hse = Some(Hse {
            freq: Hertz(25_000_000),
            mode: HseMode::Oscillator,
        });
        config.rcc.pll1 = Some(Pll {
            source: PllSource::HSE,
            prediv: PllPreDiv::DIV5,
            mul: PllMul::MUL192,
            divp: Some(PllDiv::DIV2),
            divq: Some(PllDiv::DIV2),
            divr: Some(PllDiv::DIV2),
        });
        config.rcc.sys = Sysclk::PLL1_P;
        config.rcc.ahb_pre = AHBPrescaler::DIV2;
        config.rcc.apb1_pre = APBPrescaler::DIV2;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.apb3_pre = APBPrescaler::DIV2;
        config.rcc.apb4_pre = APBPrescaler::DIV2;
        config.rcc.voltage_scale = VoltageScale::Scale0;
    }

    info!("Initialising hardware.");
    let p = embassy_stm32::init(config);
    let mut led = Output::new(p.PE3, Level::High, Speed::Low);

    let qspi_config = embassy_stm32::qspi::Config {
        fifo_threshold: FIFOThresholdLevel::_16Bytes,
        address_size: AddressSize::_32bit,
        memory_size: MemorySize::_8MiB,
        cs_high_time: ChipSelectHighTime::_1Cycle,
        prescaler: 4,
    };
    let qspi = embassy_stm32::qspi::Qspi::new_blocking_bank1(
        p.QUADSPI,
        p.PD11,
        p.PD12,
        p.PE2,
        p.PD13,
        p.PB2,
        p.PB6,
        qspi_config,
    );

    let mut flash = FlashMemory::new(qspi).await;

    let flash_id = flash.read_id();
    info!("FLASH ID: {=[u8]:x}", flash_id);
    let mut wr_buf = [0u8; 8];
    for i in 0..8 {
        wr_buf[i] = i as u8;
    }
    let mut rd_buf = [0u8; 8];
    flash.erase_sector(0).await;
    flash.write_memory(0, &wr_buf, true).await;
    flash.read_memory(0, &mut rd_buf, true);
    info!("WRITE BUF: {=[u8]:#X}", wr_buf);
    info!("READ BUF: {=[u8]:#X}", rd_buf);
    flash.enable_mm().await;
    info!("Enabled memory mapped mode");

    let first_u32 = unsafe { *(0x90000000 as *const u32) };
    assert_eq!(first_u32, 0x03020100);

    let second_u32 = unsafe { *(0x90000004 as *const u32) };
    assert_eq!(second_u32, 0x07060504);

    info!("DONE");

    loop {
        led.toggle();
        info!("Main: led toggled");
        Timer::after_millis(500).await;
    }
}

const MEMORY_PAGE_SIZE: usize = 8;

const CMD_QUAD_READ: u8 = 0x6B;

const CMD_QUAD_WRITE_PG: u8 = 0x32;

const CMD_READ_ID: u8 = 0x9F;

const CMD_ENABLE_RESET: u8 = 0x66;
const CMD_RESET: u8 = 0x99;

const CMD_WRITE_ENABLE: u8 = 0x06;

const CMD_CHIP_ERASE: u8 = 0xC7;
const CMD_SECTOR_ERASE: u8 = 0x20;
const CMD_BLOCK_ERASE_32K: u8 = 0x52;
const CMD_BLOCK_ERASE_64K: u8 = 0xD8;

const CMD_READ_SR: u8 = 0x05;
const CMD_READ_CR: u8 = 0x35;

const CMD_WRITE_SR: u8 = 0x01;
const CMD_WRITE_CR: u8 = 0x31;

/// Implementation of access to flash chip.
/// Chip commands are hardcoded as it depends on used chip.
/// This implementation is using chip GD25Q64C from Giga Device
pub struct FlashMemory<I: Instance> {
    qspi: Qspi<'static, I, Blocking>,
}

impl<I: Instance> FlashMemory<I> {
    pub async fn new(qspi: Qspi<'static, I, Blocking>) -> Self {
        let mut memory = Self { qspi };

        memory.reset_memory().await;
        memory.enable_quad();
        memory
    }

    async fn qpi_mode(&mut self) {
        // Enter qpi mode
        self.exec_command(0x38).await;

        // Set read param
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            dwidth: QspiWidth::QUAD,
            instruction: 0xC0 as u8,
            ..Default::default()
        };
        self.enable_write().await;
        self.qspi.blocking_write(&[0x30_u8], transaction);
        self.wait_write_finish();
    }

    pub async fn enable_mm(&mut self) {
        self.qpi_mode().await;

        let read_config = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::QUAD,
            instruction: 0x0B, // Fast read in QPI mode
            dummy: DummyCycles::_8,
            ..Default::default()
        };

        self.qspi.enable_memory_map(&read_config);

        /*
        let write_config = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::QUAD,
            instruction: 0x32, // Write config
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.enable_memory_map(&write_config);
        */
    }

    fn enable_quad(&mut self) {
        let cr = self.read_cr();
        // info!("Read cr: {:x}", cr);
        self.write_cr(cr | 0x02);
        // info!("Read cr after writing: {:x}", cr);
        let sr = self.read_sr();
        self.write_sr(sr | 0x02);
    }

    pub fn disable_quad(&mut self) {
        let cr = self.read_cr();
        self.write_cr(cr & (!(0x02)));
    }

    async fn exec_command_4(&mut self, cmd: u8) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::QUAD,
            awidth: QspiWidth::NONE,
            // adsize: AddressSize::_24bit,
            dwidth: QspiWidth::NONE,
            instruction: cmd as u8,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.blocking_command(transaction);
    }

    async fn exec_command(&mut self, cmd: u8) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            // adsize: AddressSize::_24bit,
            dwidth: QspiWidth::NONE,
            instruction: cmd as u8,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        // info!("Excuting command: {:x}", transaction.instruction);
        self.qspi.blocking_command(transaction);
    }

    pub async fn reset_memory(&mut self) {
        self.exec_command_4(CMD_ENABLE_RESET).await;
        self.exec_command_4(CMD_RESET).await;
        self.exec_command(CMD_ENABLE_RESET).await;
        self.exec_command(CMD_RESET).await;
        self.wait_write_finish();
    }

    pub async fn enable_write(&mut self) {
        self.exec_command(CMD_WRITE_ENABLE).await;
    }

    pub fn read_id(&mut self) -> [u8; 3] {
        let mut buffer = [0; 3];
        let transaction: TransferConfig = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            // adsize: AddressSize::_24bit,
            dwidth: QspiWidth::SING,
            instruction: CMD_READ_ID as u8,
            ..Default::default()
        };
        // info!("Reading id: 0x{:X}", transaction.instruction);
        self.qspi.blocking_read(&mut buffer, transaction);
        buffer
    }

    pub fn read_id_4(&mut self) -> [u8; 3] {
        let mut buffer = [0; 3];
        let transaction: TransferConfig = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::QUAD,
            instruction: CMD_READ_ID as u8,
            ..Default::default()
        };
        info!("Reading id: 0x{:X}", transaction.instruction);
        self.qspi.blocking_read(&mut buffer, transaction);
        buffer
    }

    pub fn read_memory(&mut self, addr: u32, buffer: &mut [u8], use_dma: bool) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::QUAD,
            instruction: CMD_QUAD_READ as u8,
            address: Some(addr),
            dummy: DummyCycles::_8,
            ..Default::default()
        };
        if use_dma {
            self.qspi.blocking_read(buffer, transaction);
        } else {
            self.qspi.blocking_read(buffer, transaction);
        }
    }

    fn wait_write_finish(&mut self) {
        while (self.read_sr() & 0x01) != 0 {}
    }

    async fn perform_erase(&mut self, addr: u32, cmd: u8) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::NONE,
            instruction: cmd as u8,
            address: Some(addr),
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.enable_write().await;
        self.qspi.blocking_command(transaction);
        self.wait_write_finish();
    }

    pub async fn erase_sector(&mut self, addr: u32) {
        self.perform_erase(addr, CMD_SECTOR_ERASE).await;
    }

    pub async fn erase_block_32k(&mut self, addr: u32) {
        self.perform_erase(addr, CMD_BLOCK_ERASE_32K).await;
    }

    pub async fn erase_block_64k(&mut self, addr: u32) {
        self.perform_erase(addr, CMD_BLOCK_ERASE_64K).await;
    }

    pub async fn erase_chip(&mut self) {
        self.exec_command(CMD_CHIP_ERASE).await;
    }

    async fn write_page(&mut self, addr: u32, buffer: &[u8], len: usize, use_dma: bool) {
        assert!(
            (len as u32 + (addr & 0x000000ff)) <= MEMORY_PAGE_SIZE as u32,
            "write_page(): page write length exceeds page boundary (len = {}, addr = {:X}",
            len,
            addr
        );

        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::QUAD,
            instruction: CMD_QUAD_WRITE_PG as u8,
            address: Some(addr),
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.enable_write().await;
        if use_dma {
            self.qspi.blocking_write(buffer, transaction);
        } else {
            self.qspi.blocking_write(buffer, transaction);
        }
        self.wait_write_finish();
    }

    pub async fn write_memory(&mut self, addr: u32, buffer: &[u8], use_dma: bool) {
        let mut left = buffer.len();
        let mut place = addr;
        let mut chunk_start = 0;

        while left > 0 {
            let max_chunk_size = MEMORY_PAGE_SIZE - (place & 0x000000ff) as usize;
            let chunk_size = if left >= max_chunk_size { max_chunk_size } else { left };
            let chunk = &buffer[chunk_start..(chunk_start + chunk_size)];
            self.write_page(place, chunk, chunk_size, use_dma).await;
            place += chunk_size as u32;
            left -= chunk_size;
            chunk_start += chunk_size;
        }
    }

    fn read_register(&mut self, cmd: u8) -> u8 {
        let mut buffer = [0; 1];
        let transaction: TransferConfig = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::SING,
            instruction: cmd as u8,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.blocking_read(&mut buffer, transaction);
        // info!("Read w25q64 register: 0x{:x}", buffer[0]);
        buffer[0]
    }

    fn write_register(&mut self, cmd: u8, value: u8) {
        let buffer = [value; 1];
        let transaction: TransferConfig = TransferConfig {
            iwidth: QspiWidth::SING,
            instruction: cmd as u8,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::SING,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.blocking_write(&buffer, transaction);
    }

    pub fn read_sr(&mut self) -> u8 {
        self.read_register(CMD_READ_SR)
    }

    pub fn read_cr(&mut self) -> u8 {
        self.read_register(CMD_READ_CR)
    }

    pub fn write_sr(&mut self, value: u8) {
        self.write_register(CMD_WRITE_SR, value);
    }

    pub fn write_cr(&mut self, value: u8) {
        self.write_register(CMD_WRITE_CR, value);
    }
}
