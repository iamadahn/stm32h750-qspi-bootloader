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
use embassy_stm32::peripherals::QUADSPI;
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
        fifo_threshold: FIFOThresholdLevel::_4Bytes,
        address_size: AddressSize::_24bit,
        memory_size: MemorySize::_8MiB,
        cs_high_time: ChipSelectHighTime::_5Cycle,
        prescaler: 2,
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

    info!("OH MY GOD - {:X} {:X}", first_u32, second_u32);

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

const W25QXX_EXIT_QSPI_MODE: u8 = 0xFF;
const W25QXX_ENTER_QSPI_MODE: u8 = 0x38;
const W25QXX_SET_READ_PARAMETERS: u8 = 0xC0; //QSPI mode only

const W25X_READ_STATUS_REG1: u8 = 0x05;
const W25X_READ_STATUS_REG2: u8 = 0x35;
const W25X_READ_STATUS_REG3: u8 = 0x15;

const W25X_WRITE_STATUS_REG1: u8 = 0x01; // Reg1 Reg2
const W25X_WRITE_STATUS_REG2: u8 = 0x01; // 0x31
const W25X_WRITE_STATUS_REG3: u8 = 0x01; // 0x11

const W25X_WRITE_ENABLE: u8 = 0x06;
const W25X_WRITE_DISABLE: u8 = 0x04;

// 添加W25QXX复位相关命令常量
const W25X_ENABLE_RESET: u8 = 0x66;
const W25X_RESET_DEVICE: u8 = 0x99;

// W25QXX读写相关命令
const W25X_FAST_READ_QUAD_IO: u8 = 0xEB; // 快速四线IO读取命令

// QE位掩码（用于检查四线模式使能）
const QE_MASK: u8 = 0x02; // 状态寄存器2中的QE位

// busy位掩码
const BUSY_MASK: u8 = 0x01;

fn w25qxx_read_sr(qspi: &mut Qspi<QUADSPI, Blocking>, srx: u8, is_qpi_mode: bool) -> u8 {
    // 选择要读取的状态寄存器指令
    let instruction = match srx {
        1 => W25X_READ_STATUS_REG1,
        2 => W25X_READ_STATUS_REG2,
        3 => W25X_READ_STATUS_REG3,
        _ => W25X_READ_STATUS_REG1, // 默认读取状态寄存器1
    };
    // 根据当前模式配置通信方式
    let (iwidth, dwidth) = if is_qpi_mode {
        (QspiWidth::QUAD, QspiWidth::QUAD)
    } else {
        (QspiWidth::SING, QspiWidth::SING)
    };

    let transaction = TransferConfig {
        iwidth,
        awidth: QspiWidth::NONE,
        dwidth,
        instruction,
        address: None,
        dummy: DummyCycles::_0,
    };

    // 创建接收缓冲区
    let mut data = [0u8; 1];
    
    // 执行读取操作
    qspi.blocking_read(&mut data, transaction);
    
    // 返回读取到的状态值
    data[0]
}

fn w25qxx_write_sr(qspi: &mut Qspi<QUADSPI, Blocking>, srx: u8, value: u8, is_qpi_mode: bool) {
    // 选择要写入的状态寄存器指令
    let instruction = match srx {
        1 => W25X_WRITE_STATUS_REG1,
        2 => W25X_WRITE_STATUS_REG2,
        3 => W25X_WRITE_STATUS_REG3,
        _ => W25X_WRITE_STATUS_REG1, // 默认写状态寄存器1
    };
    // 根据当前模式配置通信方式
    let (iwidth, dwidth) = if is_qpi_mode {
        (QspiWidth::QUAD, QspiWidth::QUAD)
    } else {
        (QspiWidth::SING, QspiWidth::SING)
    };

        // 先发送写使能指令
    w25qxx_write_enable(qspi, is_qpi_mode);

    let transaction = TransferConfig {
        iwidth,
        awidth: QspiWidth::NONE,
        dwidth,
        instruction,
        address: None,
        dummy: DummyCycles::_0,
    };

    // 创建发送缓冲区
    let data = [value];

    // 执行写入操作
    qspi.blocking_write(&data, transaction);
}

fn w25qxx_write_enable(qspi: &mut Qspi<QUADSPI, Blocking>, is_qpi_mode: bool) {
    let iwidth = if is_qpi_mode {
        QspiWidth::QUAD
    } else {
        QspiWidth::SING
    };

    let transaction = TransferConfig {
        iwidth,
        awidth: QspiWidth::NONE,
        dwidth: QspiWidth::NONE,
        instruction: CMD_WRITE_ENABLE,
        address: None,
        dummy: DummyCycles::_0,
    };

    qspi.blocking_command(transaction);
}

fn w25qxx_enter_qspi_mode(qspi: &mut Qspi<QUADSPI, Blocking>) {
    // 1. 检查并设置QE位（需要实现读写状态寄存器的函数）
    let status = w25qxx_read_sr(qspi, 2, false);
    if (status & QE_MASK) == 0 {
        // QE位未设置，需要设置
        w25qxx_write_sr(qspi, 2, status | QE_MASK, false);
    }

    // 2. 进入QSPI模式
    let transaction = TransferConfig {
        iwidth: QspiWidth::SING,
        awidth: QspiWidth::NONE,
        dwidth: QspiWidth::NONE,
        instruction: W25QXX_ENTER_QSPI_MODE,
        address: None,
        dummy: DummyCycles::_0,
    };
    qspi.blocking_command(transaction);
    // 3. 设置读参数
    let transaction = TransferConfig {
        iwidth: QspiWidth::QUAD,
        awidth: QspiWidth::NONE,
        dwidth: QspiWidth::QUAD,
        instruction: W25QXX_SET_READ_PARAMETERS,
        address: None,
        dummy: DummyCycles::_0,
    };

    // 先发送写使能指令（在QPI模式下）
    w25qxx_write_enable(qspi, true);
    let data: [u8; 1] = [0x03 << 4];
    qspi.blocking_write(&data, transaction);
}

pub struct FlashMemory {
    qspi: Qspi<'static, QUADSPI, Blocking>,
}

impl FlashMemory {
    pub async fn new(qspi: Qspi<'static, QUADSPI, Blocking>) -> Self {
        let mut memory = Self { qspi };

        memory.reset_memory().await;
        memory.enable_quad();
        memory
    }

    pub async fn enable_mm(&mut self) {
        w25qxx_enter_qspi_mode(&mut self.qspi);

        // 在embassy-stm32库中，我们需要使用memory_mapped方法来配置并启用内存映射模式
        let config = TransferConfig {
            instruction: W25X_FAST_READ_QUAD_IO,
            iwidth: QspiWidth::QUAD,
            awidth: QspiWidth::QUAD,
            dwidth: QspiWidth::QUAD,
            address: Some(24), // 24位地址
            dummy: DummyCycles::_8,
            // SIOO模式表示是否每条指令都发送指令码
            // 在embassy-stm32中，可能没有直接对应选项，使用最接近的设置
        };

        // 启用内存映射模式
        self.qspi.enable_memory_map(&config);
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
