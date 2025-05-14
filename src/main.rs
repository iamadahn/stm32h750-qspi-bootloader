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
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash, ErrorType, NorFlashError, NorFlashErrorKind};
use embassy_sync::blocking_mutex::Mutex;
use embassy_boot::*;

use core::cell::RefCell;

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
    flash.enable_mm().await;
    info!("Enabled memory mapped mode");

    let qspi_flash = Mutex::new(RefCell::new(flash));

    info!("qspi_flash");

    let config = BootLoaderConfig::from_linkerfile_blocking(&qspi_flash, &qspi_flash, &qspi_flash);
    info!("config");

    let active_offset = config.active.offset();
    info!("active_offset: {:08x}", active_offset);

    let target_addr = active_offset;

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

const CMD_ENTER_QSPI_MODE: u8 = 0x38;
const CMD_SET_READ_PARAMETERS: u8 = 0xC0;

const CMD_READ_STATUS_REG1: u8 = 0x05;
const CMD_READ_STATUS_REG2: u8 = 0x35;

const CMD_WRITE_STATUS_REG1: u8 = 0x01;
const CMD_WRITE_STATUS_REG2: u8 = 0x31;

const CMD_FAST_READ_QUAD_IO: u8 = 0xEB;  

const QE_MASK: u8 = 0x02;

pub struct FlashMemory<I: Instance> {
    qspi: Qspi<'static, I, Blocking>,
    qpi_mode: bool,
    base_address: u32,
}

impl<I: Instance> FlashMemory<I> {
    pub async fn new(qspi: Qspi<'static, I, Blocking>) -> Self {
        let mut memory = Self { qspi, qpi_mode: false, base_address: 0x9000_0000 };

        memory.reset_memory().await;
        memory.enable_quad();
        memory
    }

    pub async fn enter_qpi_mode(&mut self) {
        let status = self.read_cr();
        if (status & QE_MASK) == 0 {
            self.write_cr(status | QE_MASK);
        }

        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::NONE,
            instruction: CMD_ENTER_QSPI_MODE,
            address: None,
            dummy: DummyCycles::_0,
        };
        self.qspi.blocking_command(transaction);

        let transaction = TransferConfig {
            iwidth: QspiWidth::QUAD,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::QUAD,
            instruction: CMD_SET_READ_PARAMETERS,
            address: None,
            dummy: DummyCycles::_0,
        };

        self.qpi_mode = true;
        self.write_enable().await;
        let data: [u8; 1] = [0x03 << 4];
        self.qspi.blocking_write(&data, transaction);
    }

    pub async fn enable_mm(&mut self) {
        self.enter_qpi_mode().await;

        let config = TransferConfig {
            instruction: CMD_FAST_READ_QUAD_IO,
            iwidth: QspiWidth::QUAD,
            awidth: QspiWidth::QUAD,
            dwidth: QspiWidth::QUAD,
            address: Some(24),
            dummy: DummyCycles::_8,
        };

        self.qspi.enable_memory_map(&config);
    }

    pub fn enable_quad(&mut self) {
        let cr = self.read_cr();
        self.write_cr(cr | 0x02);

        let sr = self.read_sr();
        self.write_sr(sr | 0x02);
    }

    pub fn disable_quad(&mut self) {
        let cr = self.read_cr();
        self.write_cr(cr & (!(0x02)));
    }

    async fn exec_command(&mut self, cmd: u8) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::NONE,
            instruction: cmd as u8,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.blocking_command(transaction);
    }

    async fn exec_command_4(&mut self, cmd: u8) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::QUAD,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::NONE,
            instruction: cmd as u8,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.blocking_command(transaction);
    }

    pub async fn write_enable(&mut self) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::NONE,
            instruction: CMD_WRITE_ENABLE as u8,
            address: None,
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.qspi.blocking_command(transaction);

    }

    pub async fn reset_memory(&mut self) {
        self.exec_command_4(CMD_ENABLE_RESET).await;
        self.exec_command_4(CMD_RESET).await;
        self.exec_command(CMD_ENABLE_RESET).await;
        self.exec_command(CMD_RESET).await;
        self.wait_write_finish().await;
    }

    pub fn read_id(&mut self) -> [u8; 3] {
        let mut buffer = [0; 3];
        let transaction: TransferConfig = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::NONE,
            dwidth: QspiWidth::SING,
            instruction: CMD_READ_ID as u8,
            ..Default::default()
        };
        self.qspi.blocking_read(&mut buffer, transaction);
        buffer
    }

    pub fn read_memory(&mut self, addr: u32, buffer: &mut [u8]) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::QUAD,
            instruction: CMD_QUAD_READ as u8,
            address: Some(addr),
            dummy: DummyCycles::_8,
            ..Default::default()
        };
        self.qspi.blocking_read(buffer, transaction);
    }

    async fn wait_write_finish(&mut self) {
        while (self.read_sr() & 0x01) != 0 {}
    }

    async fn perform_erase(&mut self, addr: u32, instruction: u8) {
        let transaction = TransferConfig {
            iwidth: QspiWidth::SING,
            awidth: QspiWidth::SING,
            dwidth: QspiWidth::NONE,
            instruction,
            address: Some(addr),
            dummy: DummyCycles::_0,
            ..Default::default()
        };
        self.write_enable().await;
        self.qspi.blocking_command(transaction);
        self.wait_write_finish().await;
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
        self.write_enable().await;
        self.exec_command(CMD_CHIP_ERASE).await;
        self.wait_write_finish().await;
    }

    async fn write_page(&mut self, addr: u32, buffer: &[u8], len: usize) {
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
        self.write_enable().await;
        self.qspi.blocking_write(buffer, transaction);
        self.wait_write_finish().await;
    }

    pub async fn write_memory(&mut self, addr: u32, buffer: &[u8]) {
        let mut left = buffer.len();
        let mut place = addr;
        let mut chunk_start = 0;

        while left > 0 {
            let max_chunk_size = MEMORY_PAGE_SIZE - (place & 0x000000ff) as usize;
            let chunk_size = if left >= max_chunk_size { max_chunk_size } else { left };
            let chunk = &buffer[chunk_start..(chunk_start + chunk_size)];
            self.write_page(place, chunk, chunk_size).await;
            place += chunk_size as u32;
            left -= chunk_size;
            chunk_start += chunk_size;
        }
    }

    fn read_register(&mut self, instruction: u8) -> u8 {
        let (iwidth, dwidth) = if self.qpi_mode {
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

        let mut data = [0u8; 1];
        
        self.qspi.blocking_read(&mut data, transaction);
        
        data[0]
    }

    fn write_register(&mut self, instruction: u8, value: u8) {
        let (iwidth, dwidth) = if self.qpi_mode {
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

        let data = [value];

        self.qspi.blocking_write(&data, transaction);
    }

    pub fn read_cr(&mut self) -> u8 {
        self.read_register(CMD_READ_STATUS_REG2)
    }

    pub fn write_cr(&mut self, value: u8) {
        self.write_register(CMD_WRITE_STATUS_REG2, value);
    }

    pub fn read_sr(&mut self) -> u8 {
        self.read_register(CMD_READ_STATUS_REG1)
    }

    pub fn write_sr(&mut self, value: u8) {
        self.write_register(CMD_WRITE_STATUS_REG1, value);
    }
}

#[derive(Debug)]
pub enum QspiError {
    NotAligned,
    OutOfBounds,
    WriteError,
    EraseError,
    ReadError,
    NotReady,
}

impl NorFlashError for QspiError {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            QspiError::NotAligned => NorFlashErrorKind::NotAligned,
            QspiError::OutOfBounds => NorFlashErrorKind::OutOfBounds,
            QspiError::WriteError | QspiError::EraseError | 
            QspiError::ReadError | QspiError::NotReady => NorFlashErrorKind::Other,
        }
    }
}

impl<'d, I: Instance> ErrorType for FlashMemory<I> {
    type Error = QspiError;
}

impl<'d, I: Instance> ReadNorFlash for FlashMemory<I> {
    const READ_SIZE: usize = 1;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        if (offset as usize + bytes.len()) > (self.capacity() + self.base_address as usize) {
            return Err(QspiError::OutOfBounds);
        }
        let src_ptr = offset as *const u8;
        for (i, byte) in bytes.iter_mut().enumerate() {
            unsafe {
                *byte = core::ptr::read_volatile(src_ptr.add(i));
            }
        }
        Ok(())
    }

    fn capacity(&self) -> usize {
        8 * 1024 * 1024
    }
}

impl<'d, I: Instance> NorFlash for FlashMemory<I> {
    const WRITE_SIZE: usize = 1;
    const ERASE_SIZE: usize = 4096;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        if from > to || (to as usize) > self.capacity() {
            return Err(QspiError::OutOfBounds);
        }

        let start_sector = from / Self::ERASE_SIZE as u32;
        let end_sector = to / Self::ERASE_SIZE as u32;

        for sector in start_sector..=end_sector {
            let sector_addr = sector * Self::ERASE_SIZE as u32;

            self.write_enable();

            let iwidth = if self.qpi_mode { QspiWidth::QUAD } else { QspiWidth::SING };
            let transaction = TransferConfig {
                iwidth,
                awidth: if self.qpi_mode { QspiWidth::QUAD } else { QspiWidth::SING },
                dwidth: QspiWidth::NONE,
                instruction: CMD_SECTOR_ERASE,
                address: Some(sector_addr),
                dummy: DummyCycles::_0,
            };

            self.qspi.blocking_command(transaction);

            self.wait_write_finish();
        }

        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        if (offset as usize + bytes.len()) > self.capacity() {
            return Err(QspiError::OutOfBounds);
        }

        const PAGE_SIZE: usize = 256;

        let mut remaining = bytes.len();
        let mut src_offset = 0;
        let mut dst_offset = offset;

        while remaining > 0 {
            let current_page = (dst_offset as usize) / PAGE_SIZE;
            let bytes_in_page = ((current_page + 1) * PAGE_SIZE) - (dst_offset as usize);
            let to_write = core::cmp::min(remaining, bytes_in_page);

            self.write_enable();

            let iwidth = if self.qpi_mode { QspiWidth::QUAD } else { QspiWidth::SING };
            let cmd = if self.qpi_mode { CMD_QUAD_WRITE_PG } else { QE_MASK };
            let transaction = TransferConfig {
                iwidth,
                awidth: if self.qpi_mode { QspiWidth::QUAD } else { QspiWidth::SING },
                dwidth: if self.qpi_mode { QspiWidth::QUAD } else { QspiWidth::SING },
                instruction: cmd,
                address: Some(dst_offset),
                dummy: DummyCycles::_0,
            };

            self.qspi.blocking_write(&bytes[src_offset..(src_offset + to_write)], transaction);

            self.wait_write_finish();

            remaining -= to_write;
            src_offset += to_write;
            dst_offset += to_write as u32;
        }

        Ok(())
    }
}
