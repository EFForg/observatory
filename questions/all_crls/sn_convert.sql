-- the Serial Number field in the old datasets is annoyingly formatted.  Fix
-- it in an sn column
-- alter table valid_certs add column sn varchar(32)

update valid_certs
set sn=upper(
         replace(
           substring_index(
             substring_index(`Serial Number`,"x",-1),
             ")",
             1
           ),
           ":",
           ""
         )
       ) ;

update all_certs
set sn=upper(
         replace(
           substring_index(
             substring_index(`Serial Number`,"x",-1),
             ")",
             1
           ),
           ":",
           ""
         )
       ) ;
