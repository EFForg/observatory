-- the Serial Number field in the old datasets is annoyingly formatted.  Fix
-- it in an sn column
-- alter table valid_certs add column sn varchar(32)

update table valid_certs
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
       ) as sn ;

update table all_certs
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
       ) as sn ;
