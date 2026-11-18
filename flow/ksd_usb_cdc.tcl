# Run after board XDC, with a synthesized design and usb_clk/clk50 clocks.
# Preserve the previous async FIFO exceptions only for non-mailbox destinations.
# Mailbox held-data bundles need a real routing bound; a clock-wide false path
# would override set_max_delay and invalidate the handshake settling assumption.
set ksd_mailbox_glob "*u_ksd_mailbox/*"
set ksd_usb_registers [all_registers -clock usb_clk]
set ksd_iut_registers [all_registers -clock clk50]
set ksd_nonmail_usb [filter $ksd_usb_registers "NAME !~ $ksd_mailbox_glob"]
set ksd_nonmail_iut [filter $ksd_iut_registers "NAME !~ $ksd_mailbox_glob"]
if {[llength $ksd_nonmail_iut]} {
    set_false_path -from [get_clocks usb_clk] -to $ksd_nonmail_iut
}
if {[llength $ksd_nonmail_usb]} {
    set_false_path -from [get_clocks clk50] -to $ksd_nonmail_usb
}

proc ksd_mailbox_registers {stem} {
    # Synthesis also names LUTs/muxes after their destination register. Match
    # sequential cells only; the stem wildcard must never capture those gates.
    return [get_cells -hierarchical -quiet -filter "IS_SEQUENTIAL == 1 && NAME =~ *u_ksd_mailbox/${stem}_reg*"]
}
set ksd_secure_build [expr {![info exists ins_test_mode] || $ins_test_mode == 0}]
set ksd_bundle_pairs {
    {in_record_usb_r in_record_iut_r}
    {in_cmd_usb_r in_cmd_iut_r}
    {out_record_iut_r out_record_usb_r}
    {out_valid_iut_r out_valid_usb_r}
    {completion_result_iut_r last_result_usb_r}
}
foreach ksd_pair $ksd_bundle_pairs {
    lassign $ksd_pair ksd_source_name ksd_dest_name
    set ksd_from [ksd_mailbox_registers $ksd_source_name]
    set ksd_to [ksd_mailbox_registers $ksd_dest_name]
    puts "KSD_CDC: ${ksd_source_name}([llength $ksd_from]) -> ${ksd_dest_name}([llength $ksd_to])"
    if {![llength $ksd_from] || ![llength $ksd_to]} {
        if {$ksd_secure_build || [llength $ksd_from] || [llength $ksd_to]} {
            error "KSD_CDC: missing/partial held-data bundle $ksd_source_name -> $ksd_dest_name"
        }
        continue
    }
    set ksd_q [get_pins -of_objects $ksd_from -filter {REF_PIN_NAME == Q}]
    set ksd_d [get_pins -of_objects $ksd_to -filter {REF_PIN_NAME == D}]
    if {![llength $ksd_q] || ![llength $ksd_d]} {
        error "KSD_CDC: held-data bundle has no sequential Q/D pins"
    }
    # 10 ns is no longer than either board's USB or SoC destination period.
    # Sources remain held until acknowledgment. Record receivers add a settle
    # cycle after two synchronization stages; completion fields use the two-FF
    # notification edge. Both cases depend on this explicit 10 ns data bound.
    # Give Vivado sequential cells so it chooses valid C->Q / D timing arcs.
    # Using Q as -from would segment the path and detach its launch clock.
    # -datapath_only already removes the asynchronous hold requirement.
    set_max_delay -datapath_only 10.000 -from $ksd_from -to $ksd_to
}

foreach ksd_sync {
    in_req_sync_iut_r fault_sync_iut_r out_ack_sync_iut_r
    completion_sync_usb_r recovered_sync_usb_r out_req_sync_usb_r
} {
    set ksd_chain [ksd_mailbox_registers $ksd_sync]
    if {![llength $ksd_chain]} {
        if {$ksd_secure_build} { error "KSD_CDC: missing synchronizer $ksd_sync" }
        continue
    }
    set_property ASYNC_REG TRUE $ksd_chain
    set ksd_first_pattern [format {(^|.*/)u_ksd_mailbox/%s_reg\[0\]$} $ksd_sync]
    set ksd_first [get_cells -hierarchical -quiet -regexp -filter {IS_SEQUENTIAL == 1} $ksd_first_pattern]
    if {[llength $ksd_first] != 1} {
        error "KSD_CDC: expected one first-stage register for $ksd_sync"
    }
    set_false_path -to [get_pins -of_objects $ksd_first -filter {REF_PIN_NAME == D}]
}
foreach ksd_reset {reset_usb_r reset_iut_r} {
    set ksd_reset_chain [ksd_mailbox_registers $ksd_reset]
    if {[llength $ksd_reset_chain]} {
        set_property ASYNC_REG TRUE $ksd_reset_chain
        # Reset assertion is asynchronous; release is synchronized in each domain.
        set_false_path -to [get_pins -of_objects $ksd_reset_chain -filter {REF_PIN_NAME == CLR || REF_PIN_NAME == PRE}]
    }
}
