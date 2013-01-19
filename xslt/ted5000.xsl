<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <!-- define the timestamp as a variable-->
  <xsl:variable name="timestamp">
    <xsl:value-of select="/LiveData/GatewayTime/Month"/>-<xsl:value-of select="/LiveData/GatewayTime/Day"/>-<xsl:value-of select="/LiveData/GatewayTime/Year"/>T<xsl:value-of select="/LiveData/GatewayTime/Hour"/>:<xsl:value-of select="/LiveData/GatewayTime/Minute"/></xsl:variable>
  <xsl:template match="/">
    <smap>
      <xsl:for-each select="/LiveData/*/*/*">
	<Timeseries>
	  <xsl:attribute name="path">/<xsl:value-of select="name(../..)"/>/<xsl:value-of select="name(..)"/>/<xsl:value-of select="name(.)"/></xsl:attribute>
	  <Properties>
	    <UnitofMeasure><xsl:value-of select="name(../..)"/></UnitofMeasure>
            <ReadingType>double</ReadingType>
            <Timezone>America/Los_Angeles</Timezone>
	  </Properties>
	  <Readings>
	    <Reading>
	      <Timestamp><xsl:copy-of select="$timestamp"/></Timestamp>
              <xsl:choose>
                <xsl:when test="name(../..) = 'Voltage' and
                                not(contains(name(.), 'Date') or
                                    contains(name(.), 'Time'))">
                  <Value><xsl:value-of select=". div 10"/></Value>
                </xsl:when>
                <xsl:otherwise>
                  <Value><xsl:value-of select="."/></Value>
                </xsl:otherwise>
              </xsl:choose>
	    </Reading>
	  </Readings>
	</Timeseries>
      </xsl:for-each>
    </smap>
  </xsl:template>
</xsl:stylesheet>
