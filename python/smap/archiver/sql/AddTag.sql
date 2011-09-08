
DROP PROCEDURE IF EXISTS AddTag;

DELIMITER //

CREATE PROCEDURE AddTag(id VARCHAR(36), 
                        ref BIGINT, 
                        nextref BIGINT,
                        tagname VARCHAR(64), 
                        tagval TEXT)
  -- add a tag applying to a time reference point to the database

  -- tags apply from the reference point they are inserted at until
  -- infinity, or the next reference point which was inserted with a
  -- different tag.

  addtag:BEGIN
    DECLARE stream_id INT;
    DECLARE tmp_tagid INT;
    DECLARE tmp_tagval TEXT;
    DECLARE tmp_anchor BIGINT;
    DECLARE tmp_duration BIGINT;
    DECLARE prev_prev_tagid INT;
    DECLARE next_next_tagid INT;

    -- look up the streamid once
    SELECT s.id INTO stream_id FROM stream s WHERE `uuid` = id;
--    select stream_id;

    -- look up the tag that is previous in the tag table
    SELECT m.id,m.tagval,m.anchor,m.duration INTO tmp_tagid,tmp_tagval,tmp_anchor,tmp_duration \
           FROM metadata m \
           WHERE m.`stream_id` = stream_id AND \
                  m.`anchor` <= ref AND \
                  m.`tagname` = tagname \
           ORDER BY m.`anchor` DESC LIMIT 1;
--    select tmp_tagid;

    -- short circuit the logic if the tag is already in the db, and is right.
    IF tmp_tagid IS NOT NULL AND tmp_anchor + tmp_duration <= nextref AND tmp_tagval = tagval THEN      
    --      select 'leaving';
      LEAVE addtag;
    END IF;

    -- insert the tag by spliting if we're part of a previous range,
    -- and inserting a new record
    IF tmp_tagid IS NOT NULL THEN
      IF ref > tmp_anchor THEN 
        -- if the reference insert is after the last tag, need to
        -- shorten the last tag and insert a new tag starting at ref
        UPDATE metadata SET metadata.`duration` = ref - tmp_anchor WHERE metadata.`id` = tmp_tagid;
        INSERT INTO metadata (`stream_id`, `anchor`, `duration`, `tagname`, `tagval`) VALUES \
                (stream_id, ref, nextref - ref, tagname, tagval);
      ELSE
        -- we can just update the tag range that's in there with the
        -- new value
        UPDATE metadata m SET m.`tagval` = tagval, m.`duration` = nextref - ref WHERE m.`id` = tmp_tagid;
      END IF;

      --      SELECT tmp_duration, nextref, tmp_anchor;
      IF tmp_duration - (nextref - tmp_anchor) > 0 THEN 
        -- if the old tag included a range after the next point we need
        -- to make sure we don't change that tag.
        INSERT INTO metadata (`stream_id`, `anchor`, `duration`, `tagname`, `tagval`) VALUES \
                 (stream_id, nextref, tmp_duration - (nextref - tmp_anchor), tagname, tmp_tagval);
      END IF;
    ELSEIF tmp_tagval IS NULL OR tagval != tmp_tagval THEN
      -- if there wasn't a previous tag, we can just insert a new one.
      INSERT INTO metadata (`stream_id`, `anchor`, `duration`, `tagname`, `tagval`) VALUES \
              (stream_id, ref, nextref - ref, tagname, tagval);
    END IF;

    -- merge neighboring tag ranges if possible
    CALL MergeRef(nextref, stream_id, tagname);
    CALL MergeRef(ref, stream_id, tagname);
    IF tmp_anchor < ref THEN 
      CALL MergeRef(tmp_anchor, stream_id, tagname);
    ELSEIF tmp_anchor IS NOT NULL THEN
      SELECT anchor INTO tmp_anchor FROM metadata m \
           WHERE m.`stream_id` = stream_id AND \
                  m.`anchor` < tmp_anchor AND \
                  m.`tagname` = tagname \
           ORDER BY m.`anchor` DESC LIMIT 1;
      CALL MergeRef(tmp_anchor, stream_id, tagname);
    END IF;

  END //

DELIMITER ;

-- -- test 0 : insert into blank table
-- SELECT 'TEST 0';
-- DELETE FROM metadata;
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 4, 1000, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 6, 10, 'foo', '1');
-- SELECT * FROM metadata;

-- -- test 1 : insert before -- should merge
-- SELECT 'TEST 1';
-- DELETE FROM metadata;
-- INSERT INTO metadata VALUES (1, 1, 5, 1, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 4, 5, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 3, 4, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 2, 3, 'foo', '1');
-- SELECT * FROM metadata;

-- -- test 2 : insert before -- but there's a piece of data in the way so we can't merge immediately
-- SELECT 'TEST 2';
-- DELETE FROM metadata;
-- INSERT INTO metadata VALUES (1, 1, 5, 1, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 1, 3, 'foo', '1');
-- SELECT * FROM metadata;

-- -- test 3 : insert between -- should merge
-- SELECT 'TEST 3';
-- DELETE FROM metadata;
-- INSERT INTO metadata VALUES (1, 1, 3, 1, 'foo', '1');
-- INSERT INTO metadata VALUES (2, 1, 4, 1, 'foo', '2');
-- INSERT INTO metadata VALUES (3, 1, 5, 1, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 4, 5, 'foo', '1');
-- SELECT * FROM metadata;

-- -- test 4 : append
-- SELECT 'TEST 4';
-- DELETE FROM metadata; 
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 4, 100000000, 'foo', 'bar3');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 5, 100000000, 'foo', 'bar3');
-- -- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 6, 100000000, 'foo', 'bar3');
-- SELECT * FROM metadata;

-- -- test 5 : insert before -- should merge
-- SELECT 'TEST 5';
-- DELETE FROM metadata;
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 4, 5, 'foo', '1');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 3, 4, 'foo', '2');
-- CALL AddTag('f421c274-c3c1-11e0-851c-0026bb56ec920', 2, 3, 'foo', '1');
-- SELECT * FROM metadata;


-- DELETE FROM metadata;
-- CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Metadata/Location/Country', 'USA');
-- CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Metadata/Location/State', 'CA');

-- CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Metadata/Location/Uri', 'http://www.caiso.com/outlook/systemstatus.csv');CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Metadata/Location/Area', 'CA ISO');CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Properties/Timezone', 'America/Los_Angeles');CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Properties/UnitofMeasure', 'mWh');CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Properties/ReadingType', 'long');CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Description', 'Total demand from the CA ISO');
-- SELECT * FROM metadata;
