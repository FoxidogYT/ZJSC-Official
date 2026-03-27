use memmap2::MmapOptions;
use rayon::prelude::*;
use ahash::{AHashMap, AHashSet};
use std::fs::File;
use std::io::{Read, Write, Cursor, Seek, SeekFrom};
use memchr::memchr;
use indicatif::{ProgressBar, ProgressStyle};
use crate::error::{CompressorError, Result};
use crate::security::SecurityManager;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LatencyMode { ExtremeLow, Balanced, HighThroughput }

#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub latency_mode: LatencyMode,
    pub zstd_level: i32,
    pub auto_repair: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub show_progress: bool,
    pub threads: Option<usize>,
    pub block_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            latency_mode: LatencyMode::HighThroughput,
            zstd_level: 5,
            auto_repair: true,
            encryption_key: None,
            show_progress: true,
            threads: None,
            block_size: 64 * 1024 * 1024,
        }
    }
}

pub struct EnterpriseCompressor { pub config: CompressionConfig }

const MAGIC_V6: &[u8; 5] = b"ZJS6E";
const MAGIC_V7: &[u8; 5] = b"ZJS7E";
const MAGIC_V8: &[u8; 5] = b"ZJS8P";
const TYPE_KEY_REF: u8   = 0xFE;
const TYPE_VAL_REF: u8   = 0xFD;
const TYPE_DELTA_U64: u8 = 0xFC;
const MAGIC_INDEX: &[u8; 5]  = b"INDEX";

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BlockIndex {
    pub compressed_offset: u64,
    pub compressed_size: u32,
    pub original_offset: u64,
    pub original_size: u32,
    pub value_tags: u64, 
    pub duplicate_of: Option<usize>,
}

impl EnterpriseCompressor {
    pub fn new(config: CompressionConfig) -> Self {
        if let Some(n) = config.threads {
            rayon::ThreadPoolBuilder::new().num_threads(n).build_global().ok();
        }
        Self { config }
    }

    // ─────────────────────────────────────────────
    //  ELITE COMPRESSION: Block-Segmented V6
    // ─────────────────────────────────────────────
    pub fn compress_file(&self, input: &str, output: &str) -> Result<(usize, usize)> {
        let file = File::open(input)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let total = mmap.len();

        let pb = if self.config.show_progress {
            let b = ProgressBar::new(total as u64);
            b.set_style(ProgressStyle::with_template(
                "{spinner:.green} [V12.2 OVERLORD X-PRIME] [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA: {eta})"
            ).unwrap().progress_chars("#>-"));
            Some(b)
        } else { None };

        // ZJSC V12.3 OMEGA | PRODUCER:DAVIDE
        println!("🚀 ZJSC V12.3 OMEGA | SUPERSCALE | Powered by Davide");
        println!("🧠 [V12.3] Training context-aware 1MB dictionary...");
        let sample_size = (total / 10).min(50 * 1024 * 1024); // Sample 50MB
        let (k2id, v2id, id2k, id2v) = self.build_dictionary(&mmap[..sample_size]);
        
        // Train Zstd Dictionary for blocks
        let mut train_data = Vec::new();
        let mut train_sizes = Vec::new();
        use fastcdc::v2020::FastCDC;
        let train_cdc = FastCDC::new(&mmap[..sample_size], 256*1024, 1024*1024, 4*1024*1024);
        for c in train_cdc {
            let (p, _) = self.transform_v7(&mmap[c.offset..c.offset+c.length], &k2id, &v2id);
            train_sizes.push(p.len());
            train_data.extend(p);
        }
        let dict_limit = (train_data.len() / 4).min(1024 * 1024).max(32 * 1024);
        let trained_dict = if !train_data.is_empty() {
             zstd::dict::from_continuous(&train_data, &train_sizes, dict_limit).unwrap_or_else(|_| vec![0u8; 0])
        } else { vec![0u8; 0] };

        let mut out_file = File::create(output)?;
        out_file.write_all(MAGIC_V8)?; // Kept V8-compatible or could be V9P
        out_file.write_all(&[if self.config.encryption_key.is_some() { 1 } else { 0 }])?;

        // 2. Optimized Header (Dictionary + Trained Zstd Dict)
        let mut dict_meta = Vec::new();
        dict_meta.write_all(&(id2k.len() as u32).to_le_bytes())?;
        for k in &id2k { dict_meta.write_all(&(k.len() as u16).to_le_bytes())?; dict_meta.write_all(k)?; }
        dict_meta.write_all(&(id2v.len() as u32).to_le_bytes())?;
        for v in &id2v { dict_meta.write_all(&(v.len() as u16).to_le_bytes())?; dict_meta.write_all(v)?; }
        dict_meta.write_all(&(trained_dict.len() as u32).to_le_bytes())?;
        dict_meta.write_all(&trained_dict)?;
        
        let d_zstd = zstd::bulk::compress(&dict_meta, self.config.zstd_level)?;
        out_file.write_all(&(d_zstd.len() as u32).to_le_bytes())?;
        out_file.write_all(&d_zstd)?;

        // 3. Parallel CDC Pipeline with 1GB Long-Range Matcher (V12.2 Overlord)
        let fingerprints = dashmap::DashMap::new();
        println!("🚀 [V12.2 OVERLORD X-PRIME] Mega-Chunk Architecture Active...");
        let boundaries: Vec<(usize, usize)> = FastCDC::new(&mmap, 256*1024, 1024*1024, 4*1024*1024)
            .map(|c| (c.offset, c.length)).collect();
        
        let results: Vec<Result<(BlockIndex, Vec<u8>)>> = boundaries.into_par_iter().enumerate().map(|(id, (offset, len))| {
            let end = offset + len;
            let (block_plain, block_tags) = self.transform_v7(&mmap[offset..end], &k2id, &v2id);
            
            // V11 Overlord: Long-Range Matching
            let fingerprint = ahash::RandomState::with_seeds(1, 2, 3, 4).hash_one(&block_plain);
            
            if let Some(first_occurrence) = fingerprints.get(&fingerprint) {
                Ok((BlockIndex {
                    compressed_offset: 0,
                    compressed_size: 0,
                    original_offset: offset as u64,
                    original_size: len as u32,
                    value_tags: block_tags,
                    duplicate_of: Some(*first_occurrence),
                }, Vec::new()))
            } else {
                fingerprints.insert(fingerprint, id);

                // Use trained dictionary
                let mut compressor = zstd::bulk::Compressor::with_dictionary(self.config.zstd_level, &trained_dict)?;
                let mut block_zstd = Vec::with_capacity(len);
                compressor.compress_to_buffer(&block_plain, &mut block_zstd)?;

                let final_block = if let Some(k) = &self.config.encryption_key {
                    SecurityManager::encrypt(&block_zstd, k)?
                } else { block_zstd };

                Ok((BlockIndex {
                    compressed_offset: 0,
                    compressed_size: final_block.len() as u32,
                    original_offset: offset as u64,
                    original_size: len as u32,
                    value_tags: block_tags,
                    duplicate_of: None,
                }, final_block))
            }
        }).collect();

        // 4. Sequence & Write with Attribution (V10 Ultima)
        let mut current_pos = out_file.stream_position()?;
        let mut final_indices = Vec::new();
        
        // Permanent Attribution Tag (Embedded in Archive)
        out_file.write_all(b"PRODUCER:DAVIDE:")?; 
        current_pos += 16;

        for res in results {
            let (mut idx, data) = match res {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            
            idx.compressed_offset = current_pos;
            out_file.write_all(&data)?;
            current_pos += data.len() as u64;
            let osiz = idx.original_size;
            final_indices.push(idx);
            if let Some(ref pb) = pb { pb.inc(osiz as u64); }
        }

        // 4. Footer
        let footer_pos = out_file.stream_position()?;
        let index_bytes = serde_json::to_vec(&final_indices).unwrap();
        let index_zstd  = zstd::bulk::compress(&index_bytes, 19)?;
        out_file.write_all(&index_zstd)?;
        out_file.write_all(&(index_zstd.len() as u32).to_le_bytes())?;
        out_file.write_all(&(footer_pos as u64).to_le_bytes())?;
        out_file.write_all(b"INDEX")?; 

        if let Some(ref pb) = pb { pb.finish_with_message("V9 QUANTUM Compression Finished!"); }
        let out_size = std::fs::metadata(output)?.len() as usize;
        Ok((total, out_size))
    }

    pub fn compress_to_buffer(&self, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        if input.is_empty() { return Ok(()); }
        let (k2id, v2id, id2k, id2v) = self.build_dictionary(input);
        
        // Single Block
        let (transformed, block_tags) = self.transform_v7(input, &k2id, &v2id);
        let zstd_data = zstd::bulk::compress(&transformed, self.config.zstd_level)?;
        let final_block = if let Some(k) = &self.config.encryption_key {
            SecurityManager::encrypt(&zstd_data, k)?
        } else { zstd_data };

        output.write_all(MAGIC_V8)?;
        output.write_all(&[if self.config.encryption_key.is_some() { 1 } else { 0 }])?;
        
        // V8 Dictionary
        let mut d_buf = Vec::new();
        d_buf.write_all(&(id2k.len() as u32).to_le_bytes())?;
        for k in &id2k { d_buf.write_all(&(k.len() as u16).to_le_bytes())?; d_buf.write_all(k)?; }
        d_buf.write_all(&(id2v.len() as u32).to_le_bytes())?;
        for v in &id2v { d_buf.write_all(&(v.len() as u16).to_le_bytes())?; d_buf.write_all(v)?; }
        let d_zstd = zstd::bulk::compress(&d_buf, self.config.zstd_level)?;
        output.write_all(&(d_zstd.len() as u32).to_le_bytes())?;
        output.write_all(&d_zstd)?;
        
        output.write_all(&final_block)?;
        
        // Dummy Index for buffer-to-buffer (1 block)
        let idx = vec![BlockIndex {
            compressed_offset: 6 + 4 + d_zstd.len() as u64,
            compressed_size: final_block.len() as u32,
            original_offset: 0,
            original_size: input.len() as u32,
            value_tags: block_tags,
            duplicate_of: None,
        }];
        let i_bytes = serde_json::to_vec(&idx).unwrap();
        let i_zstd = zstd::bulk::compress(&i_bytes, 1)?;
        let f_pos = output.len() as u64;
        output.write_all(&i_zstd)?;
        output.write_all(&(i_zstd.len() as u32).to_le_bytes())?;
        output.write_all(&f_pos.to_le_bytes())?;
        output.write_all(b"INDEX")?;
        Ok(())
    }

    pub fn decompress_block(&self, archive: &str, block_id: usize) -> Result<Vec<u8>> {
        let mut file = File::open(archive)?;
        file.seek(SeekFrom::End(-17))?; 
        let mut footer_info = [0u8; 12];
        file.read_exact(&mut footer_info)?;
        let index_len = u32::from_le_bytes(footer_info[0..4].try_into().unwrap()) as usize;
        let index_pos = u64::from_le_bytes(footer_info[4..12].try_into().unwrap());
        
        file.seek(SeekFrom::Start(index_pos))?;
        let mut index_zstd = vec![0u8; index_len];
        file.read_exact(&mut index_zstd)?;
        let index_plain = zstd::bulk::decompress(&index_zstd, 1024 * 1024 * 10)?;
        let indices: Vec<BlockIndex> = serde_json::from_slice(&index_plain).unwrap();

        let mut target_id = block_id;
        while let Some(dup_id) = indices[target_id].duplicate_of {
            target_id = dup_id;
        }
        let idx = &indices[target_id];

        // Read global V7 dictionary
        file.seek(SeekFrom::Start(6))?; // Magic(5) + EncFlag(1)
        let mut dict_len_buf = [0u8; 4]; file.read_exact(&mut dict_len_buf)?;
        let dict_zlen = u32::from_le_bytes(dict_len_buf) as usize;
        let mut dict_zstd = vec![0u8; dict_zlen]; file.read_exact(&mut dict_zstd)?;
        let dict_plain = zstd::bulk::decompress(&dict_zstd, 1024 * 1024 * 256)?;

        let mut r = Cursor::new(&dict_plain);
        let mut buf4 = [0u8; 4]; r.read_exact(&mut buf4)?;
        let nk = u32::from_le_bytes(buf4) as usize;
        let mut keys = Vec::with_capacity(nk);
        for _ in 0..nk {
            let mut lb = [0u8; 2]; r.read_exact(&mut lb)?;
            let kl = u16::from_le_bytes(lb) as usize;
            let mut kb = vec![0u8; kl]; r.read_exact(&mut kb)?;
            keys.push(kb);
        }
        r.read_exact(&mut buf4)?;
        let nv = u32::from_le_bytes(buf4) as usize;
        let mut vals = Vec::with_capacity(nv);
        for _ in 0..nv {
            let mut lb = [0u8; 2]; r.read_exact(&mut lb)?;
            let vl = u16::from_le_bytes(lb) as usize;
            let mut vb = vec![0u8; vl]; r.read_exact(&mut vb)?;
            vals.push(vb);
        }
        r.read_exact(&mut buf4)?;
        let td_len = u32::from_le_bytes(buf4) as usize;
        let mut trained_dict = vec![0u8; td_len]; r.read_exact(&mut trained_dict)?;
        
        // Read block
        file.seek(SeekFrom::Start(idx.compressed_offset))?;
        let mut block_cipher = vec![0u8; idx.compressed_size as usize];
        file.read_exact(&mut block_cipher)?;

        let block_zstd = if self.config.encryption_key.is_some() {
            SecurityManager::decrypt(&block_cipher, &self.config.encryption_key.unwrap())?
        } else { block_cipher };

        let mut decompressor = zstd::bulk::Decompressor::with_dictionary(&trained_dict)?;
        let block_plain = decompressor.decompress(&block_zstd, idx.original_size as usize * 2)?;
        
        let mut out = Vec::with_capacity(idx.original_size as usize);
        self.decode_block_tokens_v7(&block_plain, &keys, &vals, &mut out)?;
        Ok(out)
    }

    pub fn decompress_file(&self, input: &str, output: &str) -> Result<()> {
        let mut file = File::open(input)?;
        let mut magic = [0u8; 5]; file.read_exact(&mut magic)?;
        if &magic != MAGIC_V8 && &magic != MAGIC_V7 {
            return Err(CompressorError::InvalidMagic("ZJS8P/ZJS7E".into(), String::from_utf8_lossy(&magic).into()));
        }
        
        let mut enc_flag = [0u8; 1]; file.read_exact(&mut enc_flag)?;
        let encrypted = enc_flag[0] == 1;

        // Read V7 Dual-Dictionary
        let mut dlen_buf = [0u8; 4]; file.read_exact(&mut dlen_buf)?;
        let dlen = u32::from_le_bytes(dlen_buf) as usize;
        let mut dzstd = vec![0u8; dlen]; file.read_exact(&mut dzstd)?;
        let dplain = zstd::bulk::decompress(&dzstd, 1024 * 1024 * 256)?; // Larger for dual-dict

        let mut r = Cursor::new(&dplain);
        // Load Keys
        let mut buf4 = [0u8; 4]; r.read_exact(&mut buf4)?;
        let nk = u32::from_le_bytes(buf4) as usize;
        let mut keys = Vec::with_capacity(nk);
        for _ in 0..nk {
            let mut lb = [0u8; 2]; r.read_exact(&mut lb)?;
            let kl = u16::from_le_bytes(lb) as usize;
            let mut kb = vec![0u8; kl]; r.read_exact(&mut kb)?;
            keys.push(kb);
        }
        // Load Values
        r.read_exact(&mut buf4)?;
        let nv = u32::from_le_bytes(buf4) as usize;
        let mut vals = Vec::with_capacity(nv);
        for _ in 0..nv {
            let mut lb = [0u8; 2]; r.read_exact(&mut lb)?;
            let vl = u16::from_le_bytes(lb) as usize;
            let mut vb = vec![0u8; vl]; r.read_exact(&mut vb)?;
            vals.push(vb);
        }
        r.read_exact(&mut buf4)?;
        let td_len = u32::from_le_bytes(buf4) as usize;
        let mut trained_dict = vec![0u8; td_len]; r.read_exact(&mut trained_dict)?;

        let mut decompressor = zstd::bulk::Decompressor::with_dictionary(&trained_dict)?;

        // Find Index
        file.seek(SeekFrom::End(-17))?;
        let mut footer = [0u8; 17]; file.read_exact(&mut footer)?;
        let idx_len = u32::from_le_bytes(footer[0..4].try_into().unwrap()) as usize;
        let idx_pos = u64::from_le_bytes(footer[4..12].try_into().unwrap());
        
        file.seek(SeekFrom::Start(idx_pos))?;
        let mut idx_zstd = vec![0u8; idx_len]; file.read_exact(&mut idx_zstd)?;
        let idx_plain = zstd::bulk::decompress(&idx_zstd, 1024 * 1024 * 10)?;
        let indices: Vec<BlockIndex> = serde_json::from_slice(&idx_plain).unwrap();

        let mut out_file = File::create(output)?;
        let mut block_cache: Vec<Vec<u8>> = Vec::with_capacity(indices.len());

        for idx in indices {
            let decompressed_tokens = if let Some(dup_id) = idx.duplicate_of {
                block_cache[dup_id].clone()
            } else {
                file.seek(SeekFrom::Start(idx.compressed_offset))?;
                let mut b_cipher = vec![0u8; idx.compressed_size as usize];
                file.read_exact(&mut b_cipher)?;

                let b_zstd = if encrypted {
                    let k = self.config.encryption_key.ok_or_else(|| CompressorError::FfiError("Key required".into()))?;
                    SecurityManager::decrypt(&b_cipher, &k)?
                } else { b_cipher };

                decompressor.decompress(&b_zstd, idx.original_size as usize * 2)?
            };

            let mut block_out = Vec::with_capacity(idx.original_size as usize);
            self.decode_block_tokens_v7(&decompressed_tokens, &keys, &vals, &mut block_out)?;
            out_file.write_all(&block_out)?;
            
            block_cache.push(decompressed_tokens);
        }
        Ok(())
    }

    pub fn decompress_to_buffer(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() < 17 { return Err(CompressorError::FfiError("Buffer too small".into())); }
        let mut cursor = Cursor::new(input);
        
        let mut magic = [0u8; 5]; cursor.read_exact(&mut magic)?;
        if &magic != MAGIC_V8 && &magic != MAGIC_V7 {
            return Err(CompressorError::InvalidMagic("ZJS8P/ZJS7E".into(), String::from_utf8_lossy(&magic).into()));
        }

        let mut enc_flag = [0u8; 1]; cursor.read_exact(&mut enc_flag)?;
        let encrypted = enc_flag[0] == 1;

        let mut dlen_buf = [0u8; 4]; cursor.read_exact(&mut dlen_buf)?;
        let dlen = u32::from_le_bytes(dlen_buf) as usize;
        let mut dzstd = vec![0u8; dlen]; cursor.read_exact(&mut dzstd)?;
        let dplain = zstd::bulk::decompress(&dzstd, 1024 * 1024 * 256)?;

        let mut r = Cursor::new(&dplain);
        let mut buf4 = [0u8; 4]; r.read_exact(&mut buf4)?;
        let nk = u32::from_le_bytes(buf4) as usize;
        let mut keys = Vec::with_capacity(nk);
        for _ in 0..nk {
            let mut lb = [0u8; 2]; r.read_exact(&mut lb)?;
            keys.push(vec![0u8; u16::from_le_bytes(lb) as usize]);
            r.read_exact(keys.last_mut().unwrap())?;
        }
        r.read_exact(&mut buf4)?;
        let nv = u32::from_le_bytes(buf4) as usize;
        let mut vals = Vec::with_capacity(nv);
        for _ in 0..nv {
            let mut lb = [0u8; 2]; r.read_exact(&mut lb)?;
            vals.push(vec![0u8; u16::from_le_bytes(lb) as usize]);
            r.read_exact(vals.last_mut().unwrap())?;
        }
        r.read_exact(&mut buf4)?;
        let td_len = u32::from_le_bytes(buf4) as usize;
        let mut trained_dict = vec![0u8; td_len]; r.read_exact(&mut trained_dict)?;

        let mut decompressor = zstd::bulk::Decompressor::with_dictionary(&trained_dict)?;

        // 1. Get Index from footer
        let foot_pos = input.len() - 17;
        let idx_len = u32::from_le_bytes(input[foot_pos..foot_pos+4].try_into().unwrap()) as usize;
        let idx_pos = u64::from_le_bytes(input[foot_pos+4..foot_pos+12].try_into().unwrap()) as usize;
        
        let idx_zstd = &input[idx_pos..idx_pos+idx_len];
        let idx_plain = zstd::bulk::decompress(idx_zstd, 1024 * 1024 * 10)?;
        let indices: Vec<BlockIndex> = serde_json::from_slice(&idx_plain).unwrap();

        let mut out = Vec::new();
        let mut block_cache: Vec<Vec<u8>> = Vec::with_capacity(indices.len());

        for idx in indices {
            let decompressed_tokens = if let Some(dup_id) = idx.duplicate_of {
                block_cache[dup_id].clone()
            } else {
                let b_zstd = &input[idx.compressed_offset as usize..(idx.compressed_offset as usize + idx.compressed_size as usize)];
                let b_dec = if encrypted {
                    let k = self.config.encryption_key.ok_or_else(|| CompressorError::FfiError("Key required".into()))?;
                    SecurityManager::decrypt(b_zstd, &k)?
                } else { b_zstd.to_vec() };

                decompressor.decompress(&b_dec, idx.original_size as usize * 2)?
            };

            self.decode_block_tokens_v7(&decompressed_tokens, &keys, &vals, &mut out)?;
            block_cache.push(decompressed_tokens);
        }
        Ok(out)
    }

    fn decode_block_tokens_v7<W: Write>(&self, data: &[u8], keys: &[Vec<u8>], vals: &[Vec<u8>], out: &mut W) -> Result<()> {
        let mut i = 0;
        let len = data.len();
        while i < len {
            let b = data[i];
            match b {
                TYPE_KEY_REF => {
                    let id = u16::from_le_bytes([data[i+1], data[i+2]]) as usize;
                    out.write_all(b"\"")?; out.write_all(&keys[id])?; out.write_all(b"\"")?;
                    i += 3;
                }
                TYPE_VAL_REF => {
                    let id = u16::from_le_bytes([data[i+1], data[i+2]]) as usize;
                    out.write_all(b"\"")?; out.write_all(&vals[id])?; out.write_all(b"\"")?;
                    i += 3;
                }
                TYPE_DELTA_U64 => {
                    let mut b8 = [0u8; 8];
                    b8.copy_from_slice(&data[i+1..i+9]);
                    let val = u64::from_le_bytes(b8);
                    out.write_all(val.to_string().as_bytes())?;
                    i += 9;
                }
                _ => {
                    out.write_all(&[b])?;
                    i += 1;
                }
            }
        }
        Ok(())
    }

    fn build_dictionary<'a>(&self, data: &'a [u8]) -> (AHashMap<&'a [u8], u16>, AHashMap<&'a [u8], u16>, Vec<&'a [u8]>, Vec<&'a [u8]>) {
        let threads = (rayon::current_num_threads() * 4).max(1);
        let csz = data.len() / threads;
        let chunks: Vec<&[u8]> = if csz < 1024 { vec![data] } else {
            let mut chunks = Vec::new(); let mut start = 0;
            while start < data.len() {
                let mut end = start + csz;
                if end >= data.len() { chunks.push(&data[start..]); break; }
                if let Some(p) = memchr(b'\n', &data[end..]) { end += p + 1; } else { end = data.len(); }
                chunks.push(&data[start..end]); start = end;
            }
            chunks
        };

        // Parallel extraction of keys AND frequent values
        let results: Vec<(AHashSet<&[u8]>, AHashSet<&[u8]>)> = chunks.par_iter().map(|c| self.extract_schema_elements(c)).collect();
        
        let mut keys_global: AHashSet<&[u8]> = AHashSet::with_capacity(2048);
        let mut vals_global: AHashSet<&[u8]> = AHashSet::with_capacity(2048);
        for (k, v) in results { keys_global.extend(k); vals_global.extend(v); }

        let mut k2id = AHashMap::with_capacity(keys_global.len());
        let mut id2k = Vec::with_capacity(keys_global.len());
        for (id, k) in keys_global.into_iter().enumerate() { k2id.insert(k, id as u16); id2k.push(k); }

        let mut v2id = AHashMap::with_capacity(vals_global.len());
        let mut id2v = Vec::with_capacity(vals_global.len());
        for (id, v) in vals_global.into_iter().enumerate() { v2id.insert(v, id as u16); id2v.push(v); }

        (k2id, v2id, id2k, id2v)
    }

    fn extract_schema_elements<'a>(&self, chunk: &'a [u8]) -> (AHashSet<&'a [u8]>, AHashSet<&'a [u8]>) {
        let mut keys = AHashSet::with_capacity(512);
        let mut vals = AHashSet::with_capacity(512);
        let mut i = 0; let len = chunk.len();
        while i < len {
            match memchr(b'"', &chunk[i..]) {
                Some(p) => {
                    i += p + 1; let start = i;
                    loop {
                        match memchr(b'"', &chunk[i..]) {
                            Some(p2) => {
                                i += p2;
                                let mut esc = 0; let mut j = i - 1;
                                while j >= start && chunk[j] == b'\\' { esc += 1; j -= 1; }
                                if esc % 2 == 0 { break; } i += 1;
                            }
                            None => { i = len; break; }
                        }
                    }
                    if i >= len { break; }
                    let s = &chunk[start..i]; i += 1;
                    
                    let mut is_key = false;
                    let mut j = i; while j < len && chunk[j].is_ascii_whitespace() { j += 1; }
                    if j < len && chunk[j] == b':' { is_key = true; i = j + 1; }

                    if is_key { keys.insert(s); }
                    else if s.len() > 3 { vals.insert(s); }
                }
                None => break,
            }
        }
        (keys, vals)
    }

    fn transform_v7<'a>(&self, chunk: &'a [u8], k2id: &AHashMap<&[u8], u16>, v2id: &AHashMap<&[u8], u16>) -> (Vec<u8>, u64) {
        let mut out = Vec::with_capacity(chunk.len());
        let mut i = 0; let len = chunk.len();
        let mut tags: u64 = 0;
        
        while i < len {
            let b = chunk[i];
            
            // Fast-Skip Whitespace
            if b <= b' ' { i += 1; continue; }

            // High-Speed Number Scanner
            if b.is_ascii_digit() {
                let start = i;
                while i < len && chunk[i].is_ascii_digit() { i += 1; }
                let ns = &chunk[start..i];
                if ns.len() >= 10 {
                    if let Ok(val) = std::str::from_utf8(ns).unwrap_or("").parse::<u64>() {
                         out.push(TYPE_DELTA_U64);
                         out.extend_from_slice(&val.to_le_bytes());
                         tags |= 1 << (val % 64);
                         continue;
                    }
                }
                out.extend_from_slice(ns);
                continue;
            }

            if b == b'"' {
                i += 1; let start = i;
                if let Some(p) = memchr(b'"', &chunk[i..]) {
                    let s = &chunk[i..i+p];
                    i += p + 1;
                    let mut j = i; while j < len && chunk[j] <= b' ' { j += 1; }
                    if j < len && chunk[j] == b':' { 
                        i = j + 1;
                        if let Some(&id) = k2id.get(s) {
                            out.push(TYPE_KEY_REF);
                            out.extend_from_slice(&id.to_le_bytes());
                            continue;
                        }
                    } else {
                        if let Some(&id) = v2id.get(s) {
                            out.push(TYPE_VAL_REF);
                            out.extend_from_slice(&id.to_le_bytes());
                            tags |= 1 << (ahash::RandomState::with_seeds(1,2,3,4).hash_one(s) % 64);
                            continue;
                        }
                    }
                    out.push(b'"'); out.extend_from_slice(s); out.push(b'"');
                    continue;
                }
            }
            out.push(b); i += 1;
        }
        (out, tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v7_roundtrip_basic() {
        let compressor = EnterpriseCompressor::new(CompressionConfig::default());
        let input = b"{\"id\": 123456789012, \"status\": \"active\", \"msg\": \"hello world\", \"status\": \"active\"}";
        let mut compressed = Vec::new();
        compressor.compress_to_buffer(input, &mut compressed).unwrap();
        
        let decompressed = compressor.decompress_to_buffer(&compressed).unwrap();
        assert_eq!(input.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_delta_encoding_detection() {
        let compressor = EnterpriseCompressor::new(CompressionConfig::default());
        let (k2id, v2id, _, _) = compressor.build_dictionary(b"");
        let input = b"123456789012"; // Should be delta encoded
        let (transformed, tags) = compressor.transform_v7(input, &k2id, &v2id);
        
        assert_eq!(transformed[0], TYPE_DELTA_U64);
        assert_ne!(tags, 0);
    }

    #[test]
    fn test_value_dictionary_tokenization() {
        let compressor = EnterpriseCompressor::new(CompressionConfig::default());
        let input = b"{\"city\": \"San Francisco\", \"city\": \"San Francisco\"}";
        let (k2id, v2id, _, _) = compressor.build_dictionary(input);
        
        assert!(v2id.contains_key(&b"San Francisco"[..]));
        
        let (transformed, _) = compressor.transform_v7(input, &k2id, &v2id);
        // Should contain TYPE_VAL_REF instead of the full string "San Francisco" in the second occurrence
        assert!(transformed.iter().any(|&b| b == TYPE_VAL_REF));
    }

    #[test]
    fn test_query_engine_search() {
        let compressor = EnterpriseCompressor::new(CompressionConfig::default());
        let input = b"{\"user\": \"david\", \"msg\": \"hello world\"}";
        let archive = "test_search.zjs7";
        
        // Manual compress to file for test
        let mut compressed = Vec::new();
        compressor.compress_to_buffer(input, &mut compressed).unwrap();
        std::fs::write(archive, &compressed).unwrap();
        
        let engine = crate::index::QueryEngine::new(&compressor);
        let results = engine.search_value(archive, "david").unwrap();
        assert!(String::from_utf8_lossy(&results).contains("david"));
        
        let results_empty = engine.search_value(archive, "nonexistent").unwrap();
        assert!(results_empty.is_empty());
        
        std::fs::remove_file(archive).ok();
    }
}
