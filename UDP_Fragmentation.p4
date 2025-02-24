#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define MF_FLAG 1
#define MAX_COUNT 340
#define MAX_SEM_ID 65535
header_type eth_hdr {
    fields {
        dst : 48;
        src : 48;
        etype : 16;
    }
}

header_type ipv4_t {
  fields {
    version : 4;
    ihl : 4;
    diffserv : 8;
    totalLen : 16;
    identification : 16;
    flags : 3;
    fragOffset : 13;
    ttl : 8;
    protocol : 8;
    hdrChecksum : 16;
    srcAddr : 32;
    dstAddr: 32;
  }
}

header_type payload_tcp_t{
    fields{
        cut:8;
    }
}

header_type payload_t{
    fields{
        cut:1480;
    }
}

header_type payload2_t{
    fields{
        cut:1480;
    }
}

header_type payload3_t{
    fields{
        cut:984;
    }
}
header_type payload4_t{
    fields{
        cut:8;
    }
}
header_type mymeta_t {
    fields {
        resubmit_count : 8;
        recirculate_count : 8;
        clone_e2e_count : 8;
        last_ing_instance_type : 8;
        f1 : 16;
        sid:16;
    }
}

header eth_hdr eth;
header  ipv4_t ipv4;
header payload_tcp_t payload_tcp;
header payload_t payloads;
header payload2_t payload2;
header payload3_t payload3;
header payload4_t payload4;
metadata mymeta_t mymeta;
primitive_action slept();
primitive_action lock_sem();
primitive_action release_sem();

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum if (ipv4.ihl == 5);
    update ipv4_checksum if (ipv4.ihl == 5);
}


parser start {
    return eth_parse;
}

parser eth_parse {
  extract(eth);
    return select(eth.etype) {
      ETHERTYPE_IPV4 : parse_ipv4;
      default: ingress;
    }

}
parser parse_ipv4 {


  extract(ipv4);
  
       return select(latest.protocol) {
        IPPROTO_UDP : parse_udp;
        default: ingress;
    }

}
parser parse_udp {
    return select(ipv4.totalLen) {
        32 : egress;
        default: parse_payload;
    }
    
}

parser parse_payload{
    extract (payloads);
    return parse_payload2;

}
parser parse_payload2{
    extract (payload2);
    return parse_payload3;

}
parser parse_payload3{
    extract (payload3);
    return parse_payload4;
}

parser parse_payload4{
     
     extract (payload4);
    return ingress;

}
field_list clone_e2e_FL {
    mymeta.clone_e2e_count;
    mymeta.recirculate_count;
    mymeta.f1;
}

field_list recirculate_FL {
    mymeta.clone_e2e_count;
    mymeta.recirculate_count;
    mymeta.f1;
}

action drop_act() {
    drop();
}
action fwd_act(espec) {
    modify_field(standard_metadata.egress_spec, espec);
}
table in_tbl {
    reads {
    standard_metadata.ingress_port : exact;
    }
    actions {
        drop_act;
        fwd_act;
    }
}
table copy_tbl {

    actions {
        
        fwd_act;
    }
}
table drop_tbl {
    reads {
    standard_metadata.instance_type : exact;
    }
    actions {
        drop_act;
    }
}
action do_clone_i2i (clone_port) {
    add_to_field(mymeta.clone_e2e_count, 1);
    clone_ingress_pkt_to_egress(clone_port | (1 << 31), clone_e2e_FL);
    add_to_field(mymeta.f1, 1);
}

table t_do_clone_i2i {
   reads {
    standard_metadata.ingress_port : exact;
    }
    actions { do_clone_i2i; }

}

action delete_tcp(){
    modify_field(ipv4.totalLen,0x05dc);
    modify_field(ipv4.flags,1);
    modify_field(standard_metadata.egress_port,0);
}

table t_delete_tcp{
    reads {
    standard_metadata.instance_type : exact;
    }
    actions { delete_tcp; }
}
action delete_ip(){
    remove_header(payloads);
    remove_header(payload2);
    remove_header(payload3);
    add_to_field(ipv4.totalLen,-370);
    modify_field(ipv4.flags,0);
}
table t_delete_ip{
    actions { delete_ip; }
}




action delete_ip2(){
    remove_header(payload4);
    add_to_field(ipv4.totalLen,-370);
    modify_field(ipv4.flags,4);
}
table t_delete_ip2{
    actions { delete_ip2; }
}



action offest_add () {
    add_to_field(ipv4.fragOffset,0xb9);
}
table t_offest_add {
    
    actions { offest_add; }
    
}

control ingress {
    
    
  apply(in_tbl);
   

  if(valid(payload2) and mymeta.recirculate_count<MAX_COUNT and ipv4.totalLen>1500 ){
    if(standard_metadata.instance_type==0 or  mymeta.recirculate_count & 0b111==0b011 )
     apply(t_do_clone_i2i);
    }

 if(standard_metadata.instance_type!=0 and valid(payload2)){
       apply(t_delete_ip) ;
     
  }
 else if(standard_metadata.instance_type!=0 ){
        
  }

  if(mymeta.recirculate_count & 0b111==0b10 ){
     apply(t_offest_add);
     apply(t_delete_ip2) ;
    }


}

 action mirror_execute(trunc_length) {
    truncate(trunc_length);
 }
 table truncate_table {

  actions {
    mirror_execute;
  }
}

action do_recirculate () {
    add_to_field(mymeta.recirculate_count, 1);
    recirculate(recirculate_FL);
}
table t_do_recirculate {
    
    actions { do_recirculate; }
    
}

action do_recirculate2 () {
    add_to_field(mymeta.recirculate_count, 4);
}
table t_do_recirculate2 {
    
    actions { do_recirculate2; }
    
}

action do_sleep() {
    slept();
}

table t_sleep {
    actions {
        do_sleep;
    }
}

action do_lock() {
    modify_field(mymeta.sid,0);
    lock_sem();
}

table t_lock_sem {
    actions {
        do_lock;
    }
}

action do_release() {
    modify_field(mymeta.sid,0);
    release_sem();
}

table t_release_sem {
    actions {
        do_release;
    }
}
action delete_ip3(){
    remove_header(payloads);
    remove_header(payload2);
    remove_header(payload3);
    add_to_field(ipv4.totalLen,-370);
    modify_field(ipv4.flags,0);
    add_to_field(mymeta.recirculate_count, 1);
}
table t_delete_ip3{
    actions { delete_ip3; }
}


control egress {

    if(standard_metadata.instance_type==0 or (mymeta.recirculate_count & 0b111==0b011 and (mymeta.recirculate_count <  MAX_COUNT) ) ){ 

       if(mymeta.f1>1){
       apply(t_do_recirculate2);
       }
       if(ipv4.totalLen>1500){
                apply(t_delete_tcp);
                apply (truncate_table);
                if(standard_metadata.instance_type==0 and valid(payload2)){
                apply(t_lock_sem);
        }

                }
       else if(standard_metadata.instance_type!=0){
                apply(t_release_sem); 
                apply(t_sleep); 
       }

              
    }
 
    else{   
	
	if(mymeta.recirculate_count & 0b111==0b111 or (mymeta.recirculate_count & 0b111==0b000 and mymeta.f1==1)){
                apply(t_delete_ip3); 
             }
        if (mymeta.recirculate_count <  MAX_COUNT) {
                apply(t_do_recirculate);
            }

    }
   
}
 