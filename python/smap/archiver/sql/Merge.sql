
DROP PROCEDURE IF EXISTS MergeRef;

DELIMITER //

CREATE PROCEDURE MergeRef(ref BIGINT, streamid INT, tagname VARCHAR(64))
  BEGIN
    DECLARE d BIGINT;
    DECLARE id_u INT;
    DECLARE id_d INT;
    DECLARE tagval_r TEXT;

    SELECT * FROM metadata;
    -- grab the id and value we're updating
    SELECT ref, streamid, tagname;
    SELECT id, tagval INTO id_u, tagval_r 
       FROM metadata m
       WHERE m.`anchor` = ref AND m.`stream_id` = streamid AND m.`tagname` = tagname;

    -- see if we can merge with the next tag
    --   we can merge if the ranges are back-to-back and the values are the same
    SELECT `id`, `duration` INTO id_d, d FROM metadata m WHERE m.`anchor` = ( \
             SELECT `anchor` + `duration` FROM metadata mm WHERE 
                  mm.`id` = id_u AND mm.`stream_id` = streamid AND mm.`tagname` = tagname) AND
             m.`stream_id` = streamid AND m.`tagname` = tagname AND m.`tagval` = tagval_r;

    IF id_u IS NOT NULL and id_d IS NOT NULL THEN
      UPDATE metadata SET metadata.`duration` = metadata.`duration` + d WHERE `id` = id_u;
      DELETE FROM metadata WHERE `id` = id_d;
    END IF;
  END //

DELIMITER ;
