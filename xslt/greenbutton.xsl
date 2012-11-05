<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:a="http://www.w3.org/2005/Atom"
                xmlns:e="http://naesb.org/espi">
  <xsl:template match="/">
    <smap>
      <!-- pull out the cost -->
      <Timeseries path="/cost">
        <Properties>
          <UnitofMeasure>$</UnitofMeasure>
          <ReadingType>long</ReadingType>
          <Timezone>America/Los_Angeles</Timezone>
        </Properties>
        <Metadata>
          <Location>
            <Text><xsl:value-of select="/a:feed/a:entry/a:title"/></Text>
          </Location>
        </Metadata>
        <Readings>
          <xsl:for-each select="/a:feed/a:entry/a:content/e:IntervalBlock/e:IntervalReading">
            <Reading>
              <Timestamp><xsl:value-of select="e:timePeriod/e:start"/></Timestamp>
              <Value><xsl:value-of select="e:cost"/></Value>
            </Reading>
          </xsl:for-each>
        </Readings>
      </Timeseries>

      <!-- pull out the interval data -->
      <Timeseries path="/usage">
        <Properties>
          <UnitofMeasure><xsl:value-of select="/a:feed/a:entry/a:content/e:ReadingType/e:uom"/></UnitofMeasure>
          <ReadingType>long</ReadingType>
          <Timezone>America/Los_Angeles</Timezone>
        </Properties>
        <Metadata>
          <Location>
            <Text><xsl:value-of select="/a:feed/a:entry/a:title"/></Text>
          </Location>
        </Metadata>
        <Readings>
          <xsl:for-each select="/a:feed/a:entry/a:content/e:IntervalBlock/e:IntervalReading">
            <Reading>
              <Timestamp><xsl:value-of select="e:timePeriod/e:start"/></Timestamp>
              <Value><xsl:value-of select="e:value"/></Value>
            </Reading>
          </xsl:for-each>
        </Readings>
      </Timeseries>
    </smap>
  </xsl:template>
</xsl:stylesheet>
