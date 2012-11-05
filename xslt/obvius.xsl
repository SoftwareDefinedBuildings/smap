<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <smap>
      <!-- pull out the cost -->
      <xsl:for-each select="/DAS/devices/device">
        <xsl:for-each select="records/record/point">
          <Timeseries>
            <xsl:attribute name="path">/<xsl:value-of select="@name"/></xsl:attribute>
            <Properties>
              <UnitofMeasure><xsl:value-of select="@units"/></UnitofMeasure>
              <ReadingType>double</ReadingType>
              <Timezone>America/Los_Angeles</Timezone>
            </Properties>
            <Description><xsl:value-of select="/DAS/name"/></Description>
            <Metadata>
              <Instrument>
                <SerialNumber><xsl:value-of select="/DAS/serial"/></SerialNumber>
                <Model><xsl:value-of select="../../../type"/></Model>
              </Instrument>
              <Location>
                <Description><xsl:value-of select="../../../name"/></Description>
              </Location>
            </Metadata>
            <Readings>
              <Reading>
                <Timestamp><xsl:value-of select="../time"/><xsl:value-of select="../time/@units"/></Timestamp>
                <Value><xsl:value-of select="@value"/></Value>
              </Reading>
            </Readings>
          </Timeseries>
        </xsl:for-each>
      </xsl:for-each>
    </smap>
  </xsl:template>
</xsl:stylesheet>
