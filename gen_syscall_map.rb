#!/usr/bin/env ruby

def maybe_add(syscalls, nums, s)
  if syscalls[s]
    nums << [syscalls[s], s]
  end
end

unistd = '/usr/include/asm/unistd_64.h'
#unistd = '/usr/include/asm/unistd_32.h'

syscalls = {}
File.readlines(unistd).each do |line|
  if line =~ /#define __NR_(\S+) (\d+)/
    syscalls[$1] = $2.to_i
  end
end

File.readlines('syscalls.tab').each do |line|
  if line =~ /^DEFINE_SYSCALL\((\w+),/
    s = $1.downcase
    nums = []
    if s == 'fstatat'
      maybe_add(syscalls, nums, 'newfstatat')
    else
      if !syscalls[s]
        raise s
      end
      nums << [syscalls[s], s]
    end

    maybe_add(syscalls, nums, "#{s}64")
    maybe_add(syscalls, nums, "#{s}32")
    if s == 'utime'
      maybe_add(syscalls, nums, "utimes")
    end

    nums.each do |n, ss|
      puts "case #{n}:  // #{ss}"
    end
    puts "  return SYSCALL_#{s.upcase};"
  end
end
