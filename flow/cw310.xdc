# CW310 pin assignments and timing constraints. The core clock is 25 MHz.

create_clock -period 5.000 -name sysclk200 [get_ports SYSCLK_P]

create_generated_clock -name clk50 -source [get_pins u_mmcm/CLKIN1] \
    -multiply_by 5 -divide_by 40 [get_pins u_mmcm/CLKOUT0]

create_clock -period 10.000 -name usb_clk [get_ports USB_CLK0]

set_clock_uncertainty -setup 0.5  [get_clocks clk50]
set_clock_uncertainty -hold  0.5  [get_clocks clk50]

set_property -dict { PACKAGE_PIN  AC9  IOSTANDARD LVDS      } [get_ports SYSCLK_P]
set_property -dict { PACKAGE_PIN  AD9  IOSTANDARD LVDS      } [get_ports SYSCLK_N]
set_property -dict { PACKAGE_PIN  AB7  IOSTANDARD LVCMOS18  } [get_ports LVDS_XO_200M_ENA]

set_property -dict { PACKAGE_PIN  Y23  IOSTANDARD LVCMOS33 } [get_ports USB_CLK0]
set_property -dict { PACKAGE_PIN AC26  IOSTANDARD LVCMOS33 } [get_ports { USB_A[0]  }]
set_property -dict { PACKAGE_PIN AD26  IOSTANDARD LVCMOS33 } [get_ports { USB_A[1]  }]
set_property -dict { PACKAGE_PIN AD25  IOSTANDARD LVCMOS33 } [get_ports { USB_A[2]  }]
set_property -dict { PACKAGE_PIN AE26  IOSTANDARD LVCMOS33 } [get_ports { USB_A[3]  }]
set_property -dict { PACKAGE_PIN AB24  IOSTANDARD LVCMOS33 } [get_ports { USB_A[4]  }]
set_property -dict { PACKAGE_PIN AC24  IOSTANDARD LVCMOS33 } [get_ports { USB_A[5]  }]
set_property -dict { PACKAGE_PIN AD24  IOSTANDARD LVCMOS33 } [get_ports { USB_A[6]  }]
set_property -dict { PACKAGE_PIN AD23  IOSTANDARD LVCMOS33 } [get_ports { USB_A[7]  }]
set_property -dict { PACKAGE_PIN AB26  IOSTANDARD LVCMOS33 } [get_ports { USB_A[8]  }]
set_property -dict { PACKAGE_PIN AB25  IOSTANDARD LVCMOS33 } [get_ports { USB_A[9]  }]
set_property -dict { PACKAGE_PIN  W23  IOSTANDARD LVCMOS33 } [get_ports { USB_A[10] }]
set_property -dict { PACKAGE_PIN  V23  IOSTANDARD LVCMOS33 } [get_ports { USB_A[11] }]
set_property -dict { PACKAGE_PIN  Y21  IOSTANDARD LVCMOS33 } [get_ports { USB_A[12] }]
set_property -dict { PACKAGE_PIN  U24  IOSTANDARD LVCMOS33 } [get_ports { USB_A[13] }]
set_property -dict { PACKAGE_PIN  U22  IOSTANDARD LVCMOS33 } [get_ports { USB_A[14] }]
set_property -dict { PACKAGE_PIN  V22  IOSTANDARD LVCMOS33 } [get_ports { USB_A[15] }]
set_property -dict { PACKAGE_PIN  U21  IOSTANDARD LVCMOS33 } [get_ports { USB_A[16] }]
set_property -dict { PACKAGE_PIN  V21  IOSTANDARD LVCMOS33 } [get_ports { USB_A[17] }]
set_property -dict { PACKAGE_PIN  W21  IOSTANDARD LVCMOS33 } [get_ports { USB_A[18] }]
set_property -dict { PACKAGE_PIN  W20  IOSTANDARD LVCMOS33 } [get_ports { USB_A[19] }]
set_property -dict { PACKAGE_PIN  U25  IOSTANDARD LVCMOS33 } [get_ports { USB_D[0]  }]
set_property -dict { PACKAGE_PIN  U26  IOSTANDARD LVCMOS33 } [get_ports { USB_D[1]  }]
set_property -dict { PACKAGE_PIN AC21  IOSTANDARD LVCMOS33 } [get_ports { USB_D[2]  }]
set_property -dict { PACKAGE_PIN  V24  IOSTANDARD LVCMOS33 } [get_ports { USB_D[3]  }]
set_property -dict { PACKAGE_PIN  V26  IOSTANDARD LVCMOS33 } [get_ports { USB_D[4]  }]
set_property -dict { PACKAGE_PIN  W26  IOSTANDARD LVCMOS33 } [get_ports { USB_D[5]  }]
set_property -dict { PACKAGE_PIN  W25  IOSTANDARD LVCMOS33 } [get_ports { USB_D[6]  }]
set_property -dict { PACKAGE_PIN  Y26  IOSTANDARD LVCMOS33 } [get_ports { USB_D[7]  }]
set_property -dict { PACKAGE_PIN AC23  IOSTANDARD LVCMOS33 } [get_ports USB_nRD]
set_property -dict { PACKAGE_PIN AA25  IOSTANDARD LVCMOS33 } [get_ports USB_nWR]
set_property -dict { PACKAGE_PIN AA23  IOSTANDARD LVCMOS33 } [get_ports USB_nCE]
set_property -dict { PACKAGE_PIN  Y25  IOSTANDARD LVCMOS33 } [get_ports USB_nALE]

set_property -dict { PACKAGE_PIN  Y7   IOSTANDARD LVCMOS18 PULLUP TRUE } [get_ports USRSW2]
set_property -dict { PACKAGE_PIN  M26  IOSTANDARD LVCMOS33 } [get_ports { USRLED[0] }]
set_property -dict { PACKAGE_PIN  M25  IOSTANDARD LVCMOS33 } [get_ports { USRLED[1] }]
set_property -dict { PACKAGE_PIN  M24  IOSTANDARD LVCMOS33 } [get_ports { USRLED[2] }]
set_property -dict { PACKAGE_PIN  M19  IOSTANDARD LVCMOS33 } [get_ports { USRLED[3] }]
set_property -dict { PACKAGE_PIN  L25  IOSTANDARD LVCMOS33 } [get_ports { USRLED[4] }]
set_property -dict { PACKAGE_PIN  K26  IOSTANDARD LVCMOS33 } [get_ports { USRLED[5] }]
set_property -dict { PACKAGE_PIN  L24  IOSTANDARD LVCMOS33 } [get_ports { USRLED[6] }]
set_property -dict { PACKAGE_PIN  K25  IOSTANDARD LVCMOS33 } [get_ports { USRLED[7] }]

set_property -dict { PACKAGE_PIN AB21  IOSTANDARD LVCMOS33 } [get_ports CWIO_HS1]
set_property -dict { PACKAGE_PIN AF24  IOSTANDARD LVCMOS33 } [get_ports CWIO_IO4]

set_property -dict { PACKAGE_PIN AB22  IOSTANDARD LVCMOS33 } [get_ports SAM_RXD0]

set_false_path -to [get_ports { USB_D[*] }]

set_false_path -to [get_ports { USRLED[*] }]
set_false_path -to [get_ports CWIO_IO4]
set_false_path -to [get_ports CWIO_HS1]
set_false_path -to [get_ports SAM_RXD0]

set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]

set_property BITSTREAM.CONFIG.USR_ACCESS TIMESTAMP [current_design]

set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets -of_objects [get_cells -hierarchical -filter {NAME =~ *trng*}]]
set_property ALLOW_COMBINATORIAL_LOOPS TRUE [get_nets -of_objects [get_cells -hierarchical -filter {NAME =~ *mask_trng*}]]
