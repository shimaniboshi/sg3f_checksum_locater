# coding: utf-8


import sys
import argparse
import struct
import binascii
import multiprocessing
from multiprocessing import shared_memory
import numpy
from scipy import stats



class ChecksumCalculator():

    HDD_CRC_TABLE = [0, 0xC0C1, 0xC181, 0x140, 0xC301, 0x3C0, 0x280, 0xC241,
        0xC601, 0x6C0, 0x780, 0xC741, 0x500, 0xC5C1, 0xC481, 0x440,
       	0xCC01, 0xCC0, 0xD80, 0xCD41, 0xF00, 0xCFC1, 0xCE81, 0xE40,
       	0xA00, 0xCAC1, 0xCB81, 0xB40, 0xC901, 0x9C0, 0x880, 0xC841,
       	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
       	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
       	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
       	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
       	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
       	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
       	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
       	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
       	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
       	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
       	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
       	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
       	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
       	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
       	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
       	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
       	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
       	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
       	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
       	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
       	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
       	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
       	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
       	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
       	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
       	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
       	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
       	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040]

    def __init__(self, data):
        
        if len(data) % 4 != 0:
            raise Exception('Data length must be a multiple of 4')
        
        self.data = data



    def __hdd_update_crc16_byte(self, data, crc):

        return ChecksumCalculator.HDD_CRC_TABLE[(data ^ crc) & 0xff] ^ ((crc >> 8) & 0xff)



    def __hdd_crc16(self, data, crc=0):
        
        for i in range(0, len(data), 4):
            crc = self.__hdd_update_crc16_byte(data[i + 3], crc)
            crc = self.__hdd_update_crc16_byte(data[i + 2], crc)
            crc = self.__hdd_update_crc16_byte(data[i + 1], crc)
            crc = self.__hdd_update_crc16_byte(data[i + 0], crc)

        return crc



    def hdd_crc16(self):        

        return self.__hdd_crc16(self.data)



    def hdd_crc16_checksum_buffer(self):

        crc = self.hdd_crc16(self.data[:-4])
        crc = (crc >> 8) ^ ChecksumCalculator.HDD_CRC_TABLE[crc & 0xff]
        crc = (crc >> 8) ^ ChecksumCalculator.HDD_CRC_TABLE[crc & 0xff]
        self.data = self.data[:-4] + ((crc >> 8) & 0xff).to_bytes(1, 'little') + (crc & 0xff).to_bytes(1, 'little') + b'\x00\x00'

        return self.data



    def successive_hdd_crc16(self, chunk_size=0x04):
       
        total_chunk, remainder = divmod(len(self.data), chunk_size)
        if remainder != 0:
            raise Exception('Chunk length must be a multiple of 4')
        
        crc = 0
        for i in range(0, total_chunk):
            crc = self.__hdd_crc16( self.data[ chunk_size * i : chunk_size * (i + 1)], crc)
            calculated_range = (0, chunk_size * (i + 1))

            #if i >= 1:
            yield crc, calculated_range
    


class RangeGenerator():

    def __init__(self, start_point, end_point, block_size):
        
        self.start_point = start_point
        self.end_point = end_point
        self.block_size = block_size

        num_of_block, remainder = divmod(end_point - start_point, block_size)
        
        self.block_num = num_of_block
        self.remainder = remainder



    def is_aligned(self):

        return self.remainder == 0


    def generate_liner_ranges(self):

        for i in range(self.block_num - 1):
            start_point = self.start_point + self.block_size * i
            end_point = self.end_point
            #if (end_point - start_point) > self.block_size:
            yield (start_point, end_point)


    def generate_mesh_ranges(self):

        for i in range(self.block_num - 1):
            for j in range(i + 1, self.block_num + 1):
                start_point = self.start_point + self.block_size * i
                end_point = self.start_point + self.block_size * j
                #if (end_point - start_point) > self.block_size:
                yield (start_point, end_point)


    def generate_single_range(self):
    
        yield (self.start_point, self.end_point)



class ChecksumResult():
    
    def __init__(self, checksum, cs_range):
        self.value = checksum
        self.range = cs_range

    def is_zero_checksum(self):
        return self.value == 0
 





def crc16_calculate(data, calc_range):

    start_point, end_point = calc_range
    calculator = ChecksumCalculator( data[start_point:end_point] )    
    checksum = calculator.hdd_crc16()
    return ChecksumResult(checksum, calc_range)



def successive_crc16_calculate(data, calc_range, chunk_size=4):
    
    start_point, end_point = calc_range
    calculator = ChecksumCalculator( data[start_point:end_point] )    
    for checksum, current_calculated_range in calculator.successive_hdd_crc16(chunk_size):
        current_start, current_end = current_calculated_range
        yield ChecksumResult(checksum, (start_point + current_start, start_point + current_end) )


def entropy_calculate(data):

    np_array = numpy.frombuffer(data, dtype = 'uint8')
    if numpy.all( np_array == 0):
        return 0.0
    else:
        return stats.entropy(np_array, 2) 




def successive_crc16_calc_loop(shm, candidates_queue, results_queue, strip_by_entropy, strip_by_size=4, strip_by_last2bytes=False, strip_by_last4bytes=False, is_verbose=False):


    while True:

        try:
            #attached_shm = multiprocessing.shared_memory.SharedMemory(shm.name)
            attached_shm = shared_memory.SharedMemory(shm.name)
   
            for cs_result in successive_crc16_calculate(attached_shm.buf, candidates_queue.get(), 4):
            
                start_point, end_point = cs_result.range

                if not cs_result.is_zero_checksum():
                    if is_verbose:
                        print('Range: 0x{0:08x} - 0x{1:08x} / Checksum: {2:04x}'.format(start_point, end_point, cs_result.value))
                    continue

                if strip_by_last4bytes:
                    if struct.unpack('<I' ,attached_shm.buf[(end_point - 4):end_point])[0] == 0:
                        if is_verbose:
                            print('Range: 0x{0:08x} - 0x{1:08x} / Stripped by last 4 bytes'.format(start_point, end_point))
                        continue

                if strip_by_last2bytes:
                    #print('[TEST]: attached_shm.buf[end_point -1] = {}'.format(attached_shm.buf[end_point-1]))
                    #print('[TEST]: attached_shm.buf[end_point -2] = {}'.format(attached_shm.buf[end_point-2]))
                    #print('[TEST]: attached_shm.buf[end_point -3] = {}'.format(attached_shm.buf[end_point-3]))
                    #print('[TEST]: attached_shm.buf[end_point -4] = {}'.format(attached_shm.buf[end_point-4]))
                    if (attached_shm.buf[(end_point - 1)] != 0) or (attached_shm.buf[(end_point - 2)] != 0):
                        if is_verbose:
                            last_4_bytes = binascii.b2a_hex( attached_shm.buf[(end_point - 4):end_point] )
                            print('Range: 0x{0:08x} - 0x{1:08x} / Stripped by last 2 bytes: {2}'.format(start_point, end_point, last_4_bytes))
                        continue

                if end_point - start_point <= strip_by_size:
                    if is_verbose:
                        print('Range: 0x{0:08x} - 0x{1:08x} / Stripped by size: {2:0d}'.format(start_point, end_point, end_point - start_point))
                    continue

                if strip_by_entropy:
                    range_entropy = entropy_calculate( attached_shm.buf[start_point:end_point] )
                    if range_entropy < strip_by_entropy:
                        if is_verbose:
                            print('Range: 0x{0:08x} - 0x{1:08x} / Stripped by entropy: {2:0f}'.format(start_point, end_point, range_entropy))
                        continue

                print('Range: 0x{0:08x} - 0x{1:08x} / Zero checksum range was found!!'.format(start_point, end_point))
                results_queue.put(cs_result)        
                #print('candidates_queue size: {0:0d}'.format(candidates_queue.qsize()))        

        # This is for 'try' section. 
        finally:
            attached_shm.close()           
            candidates_queue.task_done()




def create_processes(concurrency, worker_func, *args):

    for _ in range(concurrency):
        process = multiprocessing.Process(target=worker_func, args=(args) )
        process.daemon = True
        process.start()
  


def add_jobs_into_queue(queue, jobs):
   
    for total_job_num, job in enumerate(jobs):
        queue.put(job)
    return total_job_num + 1
    
    


def zero_checksum_locate(data, range_generator, is_bruteforce, concurrency, strip_by_entropy, strip_by_size=4, strip_by_last2bytes=False, strip_by_last4bytes=False, is_verbose=False):

    is_canceled = False
    summary = [ ]
   
    candidates_queue = multiprocessing.JoinableQueue(10_000)
    results_queue = multiprocessing.Queue()
    
    try:
        buffer_size = len(data)
        #shared_mem = multiprocessing.shared_memory.SharedMemory(create=True, size=buffer_size)
        shared_mem = shared_memory.SharedMemory(create=True, size=buffer_size)
        shared_mem.buf[:buffer_size] = data

        create_processes(concurrency, successive_crc16_calc_loop, shared_mem, candidates_queue, results_queue, strip_by_entropy, strip_by_size, strip_by_last2bytes, strip_by_last4bytes, is_verbose)
       
        if is_bruteforce:
            total_num = add_jobs_into_queue(candidates_queue, range_generator.generate_liner_ranges())
        else:
            total_num = add_jobs_into_queue(candidates_queue, range_generator.generate_single_range())


        try:
            candidates_queue.join()
        except KeyboardInterrupt:
            print('*** Canceling...')
            is_canceled = True

    finally:    
        shared_mem.close()
        shared_mem.unlink()
        print('\n*** Shared memory inter processes has been unlinked...')    

    while not results_queue.empty():
        summary += [ results_queue.get_nowait() ]

    return (summary, total_num, is_canceled)





def main():

    parser = argparse.ArgumentParser(description='Calculate checksums while increasing the start point of the range and locate zero checksum range.')
    parser.add_argument('--start', metavar='0xXXXX', nargs='?', help='Sepcify the start point of the range')
    parser.add_argument('--end', metavar='0xYYYY', nargs='?', help='Specify the end point of the range')
    parser.add_argument('--bruteforce', action='store_true', help='Increase the start point of the range while changing the end point. Without this option, start point will not be changed.') 
    parser.add_argument('--concurrency', type=int, default=multiprocessing.cpu_count(), help='Specify the number of processes created') 
    parser.add_argument('--strip_by_size', type=int, default=4, help='Exclude the result if its range is smaller than specified value') 
    parser.add_argument('--strip_by_entropy', type=float, help='Exclude the result if the calculated entropy of its range is smaller than sepcified value') 
    parser.add_argument('--strip_by_last2bytes', action='store_true', help='Exclude the result if the last 2 bytes of its range are NOT ZERO') 
    parser.add_argument('--strip_by_last4bytes', action='store_true', help='Exclude the result if the last 4 bytes of its range are ZERO') 
    parser.add_argument('--verbose', action='store_true', help='Display the all the results') 
    parser.add_argument('FILENAME',  help='target file')
    cmdline_args = parser.parse_args()

    with open(cmdline_args.FILENAME, 'rb') as f:
        data = f.read()
    
    start_point = 0
    end_point = len(data)

    if cmdline_args.start:
        start_point = int(cmdline_args.start, 0)
    
    if cmdline_args.end:
        end_point = int(cmdline_args.end, 0)

    range_generator = RangeGenerator(start_point, end_point, 0x04)   
    if not range_generator.is_aligned():
        print('Specified range must be 0x{0:0x} bytes aligned\n'.format(0x04))
        sys.exit()

    summary, total_num, is_canceled = zero_checksum_locate(data, 
                                                           range_generator, 
                                                           cmdline_args.bruteforce, 
                                                           cmdline_args.concurrency,
                                                           cmdline_args.strip_by_entropy,
                                                           cmdline_args.strip_by_size,
                                                           cmdline_args.strip_by_last2bytes,
                                                           cmdline_args.strip_by_last4bytes,
                                                           cmdline_args.verbose,
                                                           )
    

    print('-' * 80)
    if is_canceled:
        print('Process was interrupted')
    
    print('Tested Paths: {0:0d}'.format(total_num))
    
    if cmdline_args.strip_by_entropy:
        print('Ranges whose entropies were smaller than {0:0f} were excluded'.format(cmdline_args.strip_by_entropy))
    
    if cmdline_args.strip_by_last2bytes:
        print('Ranges whose last 2 bytes were NOT ZERO were excluded.')

    if cmdline_args.strip_by_last4bytes:
        print('Ranges whose last 4 bytes were ZERO were excluded.')

    print('Ranges which are smaller than {0:0d} was excluded'.format(cmdline_args.strip_by_size))
    
    print('Following is the found zero checksum ranges.')

    for cs_result in summary:
        start_point, end_point = cs_result.range
        print('Range: 0x{0:08x} - 0x{1:08x}'.format(start_point, end_point))
    print('\n')


if __name__ == '__main__':
    main()

