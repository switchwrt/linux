// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Marvell 88E6xxx SERDES manipulation, via SMI bus
 *
 * Copyright (c) 2008 Marvell Semiconductor
 *
 * Copyright (c) 2017 Andrew Lunn <andrew@lunn.ch>
 */

#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/mii.h>

#include "chip.h"
#include "global2.h"
#include "phy.h"
#include "port.h"
#include "serdes.h"

static int mv88e6352_serdes_read(struct mv88e6xxx_chip *chip, int reg,
				 u16 *val)
{
	return mv88e6xxx_phy_page_read(chip, MV88E6352_ADDR_SERDES,
				       MV88E6352_SERDES_PAGE_FIBER,
				       reg, val);
}

static int mv88e6352_serdes_write(struct mv88e6xxx_chip *chip, int reg,
				  u16 val)
{
	return mv88e6xxx_phy_page_write(chip, MV88E6352_ADDR_SERDES,
					MV88E6352_SERDES_PAGE_FIBER,
					reg, val);
}

static int mv88e6390_serdes_read(struct mv88e6xxx_chip *chip,
				 int lane, int device, int reg, u16 *val)
{
	int reg_c45 = MII_ADDR_C45 | device << 16 | reg;

	return mv88e6xxx_phy_read(chip, lane, reg_c45, val);
}

static int mv88e6390_serdes_write(struct mv88e6xxx_chip *chip,
				  int lane, int device, int reg, u16 val)
{
	int reg_c45 = MII_ADDR_C45 | device << 16 | reg;

	return mv88e6xxx_phy_write(chip, lane, reg_c45, val);
}

static int mv88e6xxx_serdes_pcs_get_state(struct mv88e6xxx_chip *chip,
					  u16 status, u16 lpa,
					  struct phylink_link_state *state)
{
	if (status & MV88E6390_SGMII_PHY_STATUS_SPD_DPL_VALID) {
		state->link = !!(status & MV88E6390_SGMII_PHY_STATUS_LINK);
		state->duplex = status &
				MV88E6390_SGMII_PHY_STATUS_DUPLEX_FULL ?
			                         DUPLEX_FULL : DUPLEX_HALF;

		if (status & MV88E6390_SGMII_PHY_STATUS_TX_PAUSE)
			state->pause |= MLO_PAUSE_TX;
		if (status & MV88E6390_SGMII_PHY_STATUS_RX_PAUSE)
			state->pause |= MLO_PAUSE_RX;

		switch (status & MV88E6390_SGMII_PHY_STATUS_SPEED_MASK) {
		case MV88E6390_SGMII_PHY_STATUS_SPEED_1000:
			if (state->interface == PHY_INTERFACE_MODE_2500BASEX)
				state->speed = SPEED_2500;
			else
				state->speed = SPEED_1000;
			break;
		case MV88E6390_SGMII_PHY_STATUS_SPEED_100:
			state->speed = SPEED_100;
			break;
		case MV88E6390_SGMII_PHY_STATUS_SPEED_10:
			state->speed = SPEED_10;
			break;
		default:
			dev_err(chip->dev, "invalid PHY speed\n");
			return -EINVAL;
		}
	} else {
		state->link = false;
	}

	if (state->interface == PHY_INTERFACE_MODE_2500BASEX)
		mii_lpa_mod_linkmode_x(state->lp_advertising, lpa,
				       ETHTOOL_LINK_MODE_2500baseX_Full_BIT);
	else if (state->interface == PHY_INTERFACE_MODE_1000BASEX)
		mii_lpa_mod_linkmode_x(state->lp_advertising, lpa,
				       ETHTOOL_LINK_MODE_1000baseX_Full_BIT);

	return 0;
}

int mv88e6352_serdes_power(struct mv88e6xxx_chip *chip, int port, int lane,
			   bool up)
{
	u16 val, new_val;
	int err;

	err = mv88e6352_serdes_read(chip, MII_BMCR, &val);
	if (err)
		return err;

	if (up)
		new_val = val & ~BMCR_PDOWN;
	else
		new_val = val | BMCR_PDOWN;

	if (val != new_val)
		err = mv88e6352_serdes_write(chip, MII_BMCR, new_val);

	return err;
}

int mv88e6352_serdes_pcs_config(struct mv88e6xxx_chip *chip, int port,
				int lane, unsigned int mode,
				phy_interface_t interface,
				const unsigned long *advertise)
{
	u16 adv, bmcr, val;
	bool changed;
	int err;

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
		adv = 0x0001;
		break;

	case PHY_INTERFACE_MODE_1000BASEX:
		adv = linkmode_adv_to_mii_adv_x(advertise,
					ETHTOOL_LINK_MODE_1000baseX_Full_BIT);
		break;

	default:
		return 0;
	}

	err = mv88e6352_serdes_read(chip, MII_ADVERTISE, &val);
	if (err)
		return err;

	changed = val != adv;
	if (changed) {
		err = mv88e6352_serdes_write(chip, MII_ADVERTISE, adv);
		if (err)
			return err;
	}

	err = mv88e6352_serdes_read(chip, MII_BMCR, &val);
	if (err)
		return err;

	if (phylink_autoneg_inband(mode))
		bmcr = val | BMCR_ANENABLE;
	else
		bmcr = val & ~BMCR_ANENABLE;

	if (bmcr == val)
		return changed;

	return mv88e6352_serdes_write(chip, MII_BMCR, bmcr);
}

int mv88e6352_serdes_pcs_get_state(struct mv88e6xxx_chip *chip, int port,
				   int lane, struct phylink_link_state *state)
{
	u16 lpa, status;
	int err;

	err = mv88e6352_serdes_read(chip, 0x11, &status);
	if (err) {
		dev_err(chip->dev, "can't read Serdes PHY status: %d\n", err);
		return err;
	}

	err = mv88e6352_serdes_read(chip, MII_LPA, &lpa);
	if (err) {
		dev_err(chip->dev, "can't read Serdes PHY LPA: %d\n", err);
		return err;
	}

	return mv88e6xxx_serdes_pcs_get_state(chip, status, lpa, state);
}

int mv88e6352_serdes_pcs_an_restart(struct mv88e6xxx_chip *chip, int port,
				    int lane)
{
	u16 bmcr;
	int err;

	err = mv88e6352_serdes_read(chip, MII_BMCR, &bmcr);
	if (err)
		return err;

	return mv88e6352_serdes_write(chip, MII_BMCR, bmcr | BMCR_ANRESTART);
}

int mv88e6352_serdes_pcs_link_up(struct mv88e6xxx_chip *chip, int port,
				 int lane, int speed, int duplex)
{
	u16 val, bmcr;
	int err;

	err = mv88e6352_serdes_read(chip, MII_BMCR, &val);
	if (err)
		return err;

	bmcr = val & ~(BMCR_SPEED100 | BMCR_FULLDPLX | BMCR_SPEED1000);
	switch (speed) {
	case SPEED_1000:
		bmcr |= BMCR_SPEED1000;
		break;
	case SPEED_100:
		bmcr |= BMCR_SPEED100;
		break;
	case SPEED_10:
		break;
	}

	if (duplex == DUPLEX_FULL)
		bmcr |= BMCR_FULLDPLX;

	if (bmcr == val)
		return 0;

	return mv88e6352_serdes_write(chip, MII_BMCR, bmcr);
}

int mv88e6352_serdes_get_lane(struct mv88e6xxx_chip *chip, int port)
{
	u8 cmode = chip->ports[port].cmode;
	int lane = -ENODEV;

	if ((cmode == MV88E6XXX_PORT_STS_CMODE_100BASEX) ||
	    (cmode == MV88E6XXX_PORT_STS_CMODE_1000BASEX) ||
	    (cmode == MV88E6XXX_PORT_STS_CMODE_SGMII))
		lane = 0xff; /* Unused */

	return lane;
}

static bool mv88e6352_port_has_serdes(struct mv88e6xxx_chip *chip, int port)
{
	if (mv88e6xxx_serdes_get_lane(chip, port) >= 0)
		return true;

	return false;
}

struct mv88e6352_serdes_hw_stat {
	char string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int reg;
};

static struct mv88e6352_serdes_hw_stat mv88e6352_serdes_hw_stats[] = {
	{ "serdes_fibre_rx_error", 16, 21 },
	{ "serdes_PRBS_error", 32, 24 },
};

int mv88e6352_serdes_get_sset_count(struct mv88e6xxx_chip *chip, int port)
{
	if (mv88e6352_port_has_serdes(chip, port))
		return ARRAY_SIZE(mv88e6352_serdes_hw_stats);

	return 0;
}

int mv88e6352_serdes_get_strings(struct mv88e6xxx_chip *chip,
				 int port, uint8_t *data)
{
	struct mv88e6352_serdes_hw_stat *stat;
	int i;

	if (!mv88e6352_port_has_serdes(chip, port))
		return 0;

	for (i = 0; i < ARRAY_SIZE(mv88e6352_serdes_hw_stats); i++) {
		stat = &mv88e6352_serdes_hw_stats[i];
		memcpy(data + i * ETH_GSTRING_LEN, stat->string,
		       ETH_GSTRING_LEN);
	}
	return ARRAY_SIZE(mv88e6352_serdes_hw_stats);
}

static uint64_t mv88e6352_serdes_get_stat(struct mv88e6xxx_chip *chip,
					  struct mv88e6352_serdes_hw_stat *stat)
{
	u64 val = 0;
	u16 reg;
	int err;

	err = mv88e6352_serdes_read(chip, stat->reg, &reg);
	if (err) {
		dev_err(chip->dev, "failed to read statistic\n");
		return 0;
	}

	val = reg;

	if (stat->sizeof_stat == 32) {
		err = mv88e6352_serdes_read(chip, stat->reg + 1, &reg);
		if (err) {
			dev_err(chip->dev, "failed to read statistic\n");
			return 0;
		}
		val = val << 16 | reg;
	}

	return val;
}

int mv88e6352_serdes_get_stats(struct mv88e6xxx_chip *chip, int port,
			       uint64_t *data)
{
	struct mv88e6xxx_port *mv88e6xxx_port = &chip->ports[port];
	struct mv88e6352_serdes_hw_stat *stat;
	u64 value;
	int i;

	if (!mv88e6352_port_has_serdes(chip, port))
		return 0;

	BUILD_BUG_ON(ARRAY_SIZE(mv88e6352_serdes_hw_stats) >
		     ARRAY_SIZE(mv88e6xxx_port->serdes_stats));

	for (i = 0; i < ARRAY_SIZE(mv88e6352_serdes_hw_stats); i++) {
		stat = &mv88e6352_serdes_hw_stats[i];
		value = mv88e6352_serdes_get_stat(chip, stat);
		mv88e6xxx_port->serdes_stats[i] += value;
		data[i] = mv88e6xxx_port->serdes_stats[i];
	}

	return ARRAY_SIZE(mv88e6352_serdes_hw_stats);
}

static void mv88e6352_serdes_irq_link(struct mv88e6xxx_chip *chip, int port)
{
	u16 bmsr;
	int err;

	/* If the link has dropped, we want to know about it. */
	err = mv88e6352_serdes_read(chip, MII_BMSR, &bmsr);
	if (err) {
		dev_err(chip->dev, "can't read Serdes BMSR: %d\n", err);
		return;
	}

	dsa_port_phylink_mac_change(chip->ds, port, !!(bmsr & BMSR_LSTATUS));
}

irqreturn_t mv88e6352_serdes_irq_status(struct mv88e6xxx_chip *chip, int port,
					int lane)
{
	irqreturn_t ret = IRQ_NONE;
	u16 status;
	int err;

	err = mv88e6352_serdes_read(chip, MV88E6352_SERDES_INT_STATUS, &status);
	if (err)
		return ret;

	if (status & MV88E6352_SERDES_INT_LINK_CHANGE) {
		ret = IRQ_HANDLED;
		mv88e6352_serdes_irq_link(chip, port);
	}

	return ret;
}

int mv88e6352_serdes_irq_enable(struct mv88e6xxx_chip *chip, int port, int lane,
				bool enable)
{
	u16 val = 0;

	if (enable)
		val |= MV88E6352_SERDES_INT_LINK_CHANGE;

	return mv88e6352_serdes_write(chip, MV88E6352_SERDES_INT_ENABLE, val);
}

unsigned int mv88e6352_serdes_irq_mapping(struct mv88e6xxx_chip *chip, int port)
{
	return irq_find_mapping(chip->g2_irq.domain, MV88E6352_SERDES_IRQ);
}

int mv88e6352_serdes_get_regs_len(struct mv88e6xxx_chip *chip, int port)
{
	if (!mv88e6352_port_has_serdes(chip, port))
		return 0;

	return 32 * sizeof(u16);
}

void mv88e6352_serdes_get_regs(struct mv88e6xxx_chip *chip, int port, void *_p)
{
	u16 *p = _p;
	u16 reg;
	int i;

	if (!mv88e6352_port_has_serdes(chip, port))
		return;

	for (i = 0 ; i < 32; i++) {
		mv88e6352_serdes_read(chip, i, &reg);
		p[i] = reg;
	}
}

int mv88e6341_serdes_get_lane(struct mv88e6xxx_chip *chip, int port)
{
	u8 cmode = chip->ports[port].cmode;
	int lane = -ENODEV;

	switch (port) {
	case 5:
		if (cmode == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_2500BASEX)
			lane = MV88E6341_PORT5_LANE;
		break;
	}

	return lane;
}

int mv88e6390_serdes_get_lane(struct mv88e6xxx_chip *chip, int port)
{
	u8 cmode = chip->ports[port].cmode;
	int lane = -ENODEV;

	switch (port) {
	case 9:
		if (cmode == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_2500BASEX)
			lane = MV88E6390_PORT9_LANE0;
		break;
	case 10:
		if (cmode == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_2500BASEX)
			lane = MV88E6390_PORT10_LANE0;
		break;
	}

	return lane;
}

int mv88e6390x_serdes_get_lane(struct mv88e6xxx_chip *chip, int port)
{
	u8 cmode_port = chip->ports[port].cmode;
	u8 cmode_port10 = chip->ports[10].cmode;
	u8 cmode_port9 = chip->ports[9].cmode;
	int lane = -ENODEV;

	switch (port) {
	case 2:
		if (cmode_port9 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_2500BASEX)
			if (cmode_port == MV88E6XXX_PORT_STS_CMODE_1000BASEX)
				lane = MV88E6390_PORT9_LANE1;
		break;
	case 3:
		if (cmode_port9 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_RXAUI)
			if (cmode_port == MV88E6XXX_PORT_STS_CMODE_1000BASEX)
				lane = MV88E6390_PORT9_LANE2;
		break;
	case 4:
		if (cmode_port9 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_RXAUI)
			if (cmode_port == MV88E6XXX_PORT_STS_CMODE_1000BASEX)
				lane = MV88E6390_PORT9_LANE3;
		break;
	case 5:
		if (cmode_port10 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_2500BASEX)
			if (cmode_port == MV88E6XXX_PORT_STS_CMODE_1000BASEX)
				lane = MV88E6390_PORT10_LANE1;
		break;
	case 6:
		if (cmode_port10 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_RXAUI)
			if (cmode_port == MV88E6XXX_PORT_STS_CMODE_1000BASEX)
				lane = MV88E6390_PORT10_LANE2;
		break;
	case 7:
		if (cmode_port10 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_RXAUI)
			if (cmode_port == MV88E6XXX_PORT_STS_CMODE_1000BASEX)
				lane = MV88E6390_PORT10_LANE3;
		break;
	case 9:
		if (cmode_port9 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_XAUI ||
		    cmode_port9 == MV88E6XXX_PORT_STS_CMODE_RXAUI)
			lane = MV88E6390_PORT9_LANE0;
		break;
	case 10:
		if (cmode_port10 == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_XAUI ||
		    cmode_port10 == MV88E6XXX_PORT_STS_CMODE_RXAUI)
			lane = MV88E6390_PORT10_LANE0;
		break;
	}

	return lane;
}

/* Only Ports 0, 9 and 10 have SERDES lanes. Return the SERDES lane address
 * a port is using else Returns -ENODEV.
 */
int mv88e6393x_serdes_get_lane(struct mv88e6xxx_chip *chip, int port)
{
	u8 cmode = chip->ports[port].cmode;
	int lane = -ENODEV;

	if (port == 0 || port == 9 || port == 10) {
		if (cmode == MV88E6XXX_PORT_STS_CMODE_1000BASEX ||
			cmode == MV88E6XXX_PORT_STS_CMODE_SGMII ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_2500BASEX ||
			cmode == MV88E6XXX_PORT_STS_CMODE_5GBASER ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_10GBASER ||
		    cmode == MV88E6XXX_PORT_STS_CMODE_USXGMII)
			lane = port;
	}
	return lane;
}

/* Set power up/down for 10GBASE-R and 10GBASE-X4/X2 */
static int mv88e6390_serdes_power_10g(struct mv88e6xxx_chip *chip, int lane,
				      bool up)
{
	u16 val, new_val;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_10G_CTRL1, &val);

	if (err)
		return err;

	if (up)
		new_val = val & ~(MDIO_CTRL1_RESET |
				  MDIO_PCS_CTRL1_LOOPBACK |
				  MDIO_CTRL1_LPOWER);
	else
		new_val = val | MDIO_CTRL1_LPOWER;

	if (val != new_val)
		err = mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
					     MV88E6390_10G_CTRL1, new_val);

	return err;
}

/* Set power up/down for SGMII and 1000Base-X */
static int mv88e6390_serdes_power_sgmii(struct mv88e6xxx_chip *chip, int lane,
					bool up)
{
	u16 val, new_val;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_BMCR, &val);
	if (err)
		return err;

	if (up)
		new_val = val & ~(BMCR_RESET | BMCR_LOOPBACK | BMCR_PDOWN);
	else
		new_val = val | BMCR_PDOWN;

	if (val != new_val)
		err = mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
					     MV88E6390_SGMII_BMCR, new_val);

	return err;
}

struct mv88e6390_serdes_hw_stat {
	char string[ETH_GSTRING_LEN];
	int reg;
};

static struct mv88e6390_serdes_hw_stat mv88e6390_serdes_hw_stats[] = {
	{ "serdes_rx_pkts", 0xf021 },
	{ "serdes_rx_bytes", 0xf024 },
	{ "serdes_rx_pkts_error", 0xf027 },
};

int mv88e6390_serdes_get_sset_count(struct mv88e6xxx_chip *chip, int port)
{
	if (mv88e6390_serdes_get_lane(chip, port) < 0)
		return 0;

	return ARRAY_SIZE(mv88e6390_serdes_hw_stats);
}

int mv88e6390_serdes_get_strings(struct mv88e6xxx_chip *chip,
				 int port, uint8_t *data)
{
	struct mv88e6390_serdes_hw_stat *stat;
	int i;

	if (mv88e6390_serdes_get_lane(chip, port) < 0)
		return 0;

	for (i = 0; i < ARRAY_SIZE(mv88e6390_serdes_hw_stats); i++) {
		stat = &mv88e6390_serdes_hw_stats[i];
		memcpy(data + i * ETH_GSTRING_LEN, stat->string,
		       ETH_GSTRING_LEN);
	}
	return ARRAY_SIZE(mv88e6390_serdes_hw_stats);
}

static uint64_t mv88e6390_serdes_get_stat(struct mv88e6xxx_chip *chip, int lane,
					  struct mv88e6390_serdes_hw_stat *stat)
{
	u16 reg[3];
	int err, i;

	for (i = 0; i < 3; i++) {
		err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
					    stat->reg + i, &reg[i]);
		if (err) {
			dev_err(chip->dev, "failed to read statistic\n");
			return 0;
		}
	}

	return reg[0] | ((u64)reg[1] << 16) | ((u64)reg[2] << 32);
}

int mv88e6390_serdes_get_stats(struct mv88e6xxx_chip *chip, int port,
			       uint64_t *data)
{
	struct mv88e6390_serdes_hw_stat *stat;
	int lane;
	int i;

	lane = mv88e6390_serdes_get_lane(chip, port);
	if (lane < 0)
		return 0;

	for (i = 0; i < ARRAY_SIZE(mv88e6390_serdes_hw_stats); i++) {
		stat = &mv88e6390_serdes_hw_stats[i];
		data[i] = mv88e6390_serdes_get_stat(chip, lane, stat);
	}

	return ARRAY_SIZE(mv88e6390_serdes_hw_stats);
}

static int mv88e6390_serdes_enable_checker(struct mv88e6xxx_chip *chip, int lane)
{
	u16 reg;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_PG_CONTROL, &reg);
	if (err)
		return err;

	reg |= MV88E6390_PG_CONTROL_ENABLE_PC;
	return mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				      MV88E6390_PG_CONTROL, reg);
}

int mv88e6390_serdes_power(struct mv88e6xxx_chip *chip, int port, int lane,
			   bool up)
{
	u8 cmode = chip->ports[port].cmode;
	int err = 0;

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_SGMII:
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
		err = mv88e6390_serdes_power_sgmii(chip, lane, up);
		break;
	case MV88E6XXX_PORT_STS_CMODE_XAUI:
	case MV88E6XXX_PORT_STS_CMODE_RXAUI:
		err = mv88e6390_serdes_power_10g(chip, lane, up);
		break;
	}

	if (!err && up)
		err = mv88e6390_serdes_enable_checker(chip, lane);

	return err;
}

int mv88e6390_serdes_pcs_config(struct mv88e6xxx_chip *chip, int port,
				int lane, unsigned int mode,
				phy_interface_t interface,
				const unsigned long *advertise)
{
	u16 val, bmcr, adv;
	bool changed;
	int err;

	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
		adv = 0x0001;
		break;

	case PHY_INTERFACE_MODE_1000BASEX:
		adv = linkmode_adv_to_mii_adv_x(advertise,
					ETHTOOL_LINK_MODE_1000baseX_Full_BIT);
		break;

	case PHY_INTERFACE_MODE_2500BASEX:
		adv = linkmode_adv_to_mii_adv_x(advertise,
					ETHTOOL_LINK_MODE_2500baseX_Full_BIT);
		break;

	default:
		return 0;
	}

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_ADVERTISE, &val);
	if (err)
		return err;

	changed = val != adv;
	if (changed) {
		err = mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
					     MV88E6390_SGMII_ADVERTISE, adv);
		if (err)
			return err;
	}

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_BMCR, &val);
	if (err)
		return err;

	if (phylink_autoneg_inband(mode))
		bmcr = val | BMCR_ANENABLE;
	else
		bmcr = val & ~BMCR_ANENABLE;

	/* setting ANENABLE triggers a restart of negotiation */
	if (bmcr == val)
		return changed;

	return mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				      MV88E6390_SGMII_BMCR, bmcr);
}

static int mv88e6390_serdes_pcs_get_state_sgmii(struct mv88e6xxx_chip *chip,
	int port, int lane, struct phylink_link_state *state)
{
	u16 lpa, status;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_PHY_STATUS, &status);
	if (err) {
		dev_err(chip->dev, "can't read Serdes PHY status: %d\n", err);
		return err;
	}

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_LPA, &lpa);
	if (err) {
		dev_err(chip->dev, "can't read Serdes PHY LPA: %d\n", err);
		return err;
	}

	return mv88e6xxx_serdes_pcs_get_state(chip, status, lpa, state);
}

static int mv88e6390_serdes_pcs_get_state_10g(struct mv88e6xxx_chip *chip,
	int port, int lane, struct phylink_link_state *state)
{
	u16 status;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_10G_STAT1, &status);
	if (err)
		return err;

	state->link = !!(status & MDIO_STAT1_LSTATUS);
	if (state->link) {
		state->speed = SPEED_10000;
		state->duplex = DUPLEX_FULL;
	}

	return 0;
}

int mv88e6390_serdes_pcs_get_state(struct mv88e6xxx_chip *chip, int port,
				   int lane, struct phylink_link_state *state)
{
	switch (state->interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
	case PHY_INTERFACE_MODE_2500BASEX:
		return mv88e6390_serdes_pcs_get_state_sgmii(chip, port, lane,
							    state);
	case PHY_INTERFACE_MODE_XAUI:
	case PHY_INTERFACE_MODE_RXAUI:
		return mv88e6390_serdes_pcs_get_state_10g(chip, port, lane,
							  state);

	default:
		return -EOPNOTSUPP;
	}
}

int mv88e6390_serdes_pcs_an_restart(struct mv88e6xxx_chip *chip, int port,
				    int lane)
{
	u16 bmcr;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_BMCR, &bmcr);
	if (err)
		return err;

	return mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				      MV88E6390_SGMII_BMCR,
				      bmcr | BMCR_ANRESTART);
}

int mv88e6390_serdes_pcs_link_up(struct mv88e6xxx_chip *chip, int port,
				 int lane, int speed, int duplex)
{
	u16 val, bmcr;
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_BMCR, &val);
	if (err)
		return err;

	bmcr = val & ~(BMCR_SPEED100 | BMCR_FULLDPLX | BMCR_SPEED1000);
	switch (speed) {
	case SPEED_2500:
	case SPEED_1000:
		bmcr |= BMCR_SPEED1000;
		break;
	case SPEED_100:
		bmcr |= BMCR_SPEED100;
		break;
	case SPEED_10:
		break;
	}

	if (duplex == DUPLEX_FULL)
		bmcr |= BMCR_FULLDPLX;

	if (bmcr == val)
		return 0;

	return mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				      MV88E6390_SGMII_BMCR, bmcr);
}

static void mv88e6390_serdes_irq_link_sgmii(struct mv88e6xxx_chip *chip,
					    int port, int lane)
{
	u16 bmsr;
	int err;

	/* If the link has dropped, we want to know about it. */
	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_BMSR, &bmsr);
	if (err) {
		dev_err(chip->dev, "can't read Serdes BMSR: %d\n", err);
		return;
	}

	dsa_port_phylink_mac_change(chip->ds, port, !!(bmsr & BMSR_LSTATUS));
}

static int mv88e6390_serdes_irq_enable_sgmii(struct mv88e6xxx_chip *chip,
					     int lane, bool enable)
{
	u16 val = 0;

	if (enable)
		val |= MV88E6390_SGMII_INT_LINK_DOWN |
			MV88E6390_SGMII_INT_LINK_UP;

	return mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				      MV88E6390_SGMII_INT_ENABLE, val);
}

int mv88e6390_serdes_irq_enable(struct mv88e6xxx_chip *chip, int port, int lane,
				bool enable)
{
	u8 cmode = chip->ports[port].cmode;

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_SGMII:
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
		return mv88e6390_serdes_irq_enable_sgmii(chip, lane, enable);
	}

	return 0;
}

static int mv88e6390_serdes_irq_status_sgmii(struct mv88e6xxx_chip *chip,
					     int lane, u16 *status)
{
	int err;

	err = mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				    MV88E6390_SGMII_INT_STATUS, status);

	return err;
}

int mv88e6393x_serdes_irq_enable(struct mv88e6xxx_chip *chip, int port,
	    int lane, bool enable)
{
	u8 cmode = chip->ports[port].cmode;
	int err = 0;

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_SGMII:
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
	case MV88E6XXX_PORT_STS_CMODE_5GBASER:
	case MV88E6XXX_PORT_STS_CMODE_10GBASER:
		err = mv88e6390_serdes_irq_enable_sgmii(chip, lane, enable);
	}

	return err;
}

irqreturn_t mv88e6393x_serdes_irq_status(struct mv88e6xxx_chip *chip, int port,
				 int lane)
{
	u8 cmode = chip->ports[port].cmode;
	irqreturn_t ret = IRQ_NONE;
	u16 status;
	int err;

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_SGMII:
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
	case MV88E6XXX_PORT_STS_CMODE_5GBASER:
	case MV88E6XXX_PORT_STS_CMODE_10GBASER:
		err = mv88e6390_serdes_irq_status_sgmii(chip, lane, &status);
		if (err)
			return ret;
		if (status & (MV88E6390_SGMII_INT_LINK_DOWN |
			      MV88E6390_SGMII_INT_LINK_UP)) {
			ret = IRQ_HANDLED;
			mv88e6390_serdes_irq_link_sgmii(chip, port, lane);
		}
	}

	return ret;
}

irqreturn_t mv88e6390_serdes_irq_status(struct mv88e6xxx_chip *chip, int port,
					int lane)
{
	u8 cmode = chip->ports[port].cmode;
	irqreturn_t ret = IRQ_NONE;
	u16 status;
	int err;

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_SGMII:
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
		err = mv88e6390_serdes_irq_status_sgmii(chip, lane, &status);
		if (err)
			return ret;
		if (status & (MV88E6390_SGMII_INT_LINK_DOWN |
			      MV88E6390_SGMII_INT_LINK_UP)) {
			ret = IRQ_HANDLED;
			mv88e6390_serdes_irq_link_sgmii(chip, port, lane);
		}
	}

	return ret;
}

unsigned int mv88e6390_serdes_irq_mapping(struct mv88e6xxx_chip *chip, int port)
{
	return irq_find_mapping(chip->g2_irq.domain, port);
}

static const u16 mv88e6390_serdes_regs[] = {
	/* SERDES common registers */
	0xf00a, 0xf00b, 0xf00c,
	0xf010, 0xf011, 0xf012, 0xf013,
	0xf016, 0xf017, 0xf018,
	0xf01b, 0xf01c, 0xf01d, 0xf01e, 0xf01f,
	0xf020, 0xf021, 0xf022, 0xf023, 0xf024, 0xf025, 0xf026, 0xf027,
	0xf028, 0xf029,
	0xf030, 0xf031, 0xf032, 0xf033, 0xf034, 0xf035, 0xf036, 0xf037,
	0xf038, 0xf039,
	/* SGMII */
	0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
	0x2008,
	0x200f,
	0xa000, 0xa001, 0xa002, 0xa003,
	/* 10Gbase-X */
	0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007,
	0x1008,
	0x100e, 0x100f,
	0x1018, 0x1019,
	0x9000, 0x9001, 0x9002, 0x9003, 0x9004,
	0x9006,
	0x9010, 0x9011, 0x9012, 0x9013, 0x9014, 0x9015, 0x9016,
	/* 10Gbase-R */
	0x1020, 0x1021, 0x1022, 0x1023, 0x1024, 0x1025, 0x1026, 0x1027,
	0x1028, 0x1029, 0x102a, 0x102b,
};

int mv88e6390_serdes_get_regs_len(struct mv88e6xxx_chip *chip, int port)
{
	if (mv88e6xxx_serdes_get_lane(chip, port) < 0)
		return 0;

	return ARRAY_SIZE(mv88e6390_serdes_regs) * sizeof(u16);
}

void mv88e6390_serdes_get_regs(struct mv88e6xxx_chip *chip, int port, void *_p)
{
	u16 *p = _p;
	int lane;
	u16 reg;
	int i;

	lane = mv88e6xxx_serdes_get_lane(chip, port);
	if (lane < 0)
		return;

	for (i = 0 ; i < ARRAY_SIZE(mv88e6390_serdes_regs); i++) {
		mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				      mv88e6390_serdes_regs[i], &reg);
		p[i] = reg;
	}
}

int mv88e6393x_setup_errata(struct mv88e6xxx_chip *chip)
{
	u16 config0, config9, config10;
	u16 pcs0, pcs9, pcs10;
	int err = 0;

	/* mv88e6393x family errata 3.8 :
	 * When a SERDES port is operating in 1000BASE-X or SGMII mode link may not
	 * come up after hardware reset or software reset of SERDES core.
	 * Workaround is to write SERDES register 4.F074.14 =1 for only those modes
	 * and 0 in all other modes.
	 */
	err = mv88e6390_serdes_read(chip, MV88E6393X_PORT0_LANE, MDIO_MMD_PHYXS,
				    MV88E6393X_ERRATA_1000BASEX_SGMII, &config0);
	err = mv88e6390_serdes_read(chip, MV88E6393X_PORT9_LANE, MDIO_MMD_PHYXS,
				    MV88E6393X_ERRATA_1000BASEX_SGMII, &config9);
	err = mv88e6390_serdes_read(chip, MV88E6393X_PORT10_LANE, MDIO_MMD_PHYXS,
				    MV88E6393X_ERRATA_1000BASEX_SGMII, &config10);

	err = mv88e6390_serdes_read(chip, MV88E6393X_PORT0_LANE, MDIO_MMD_PHYXS,
				    MV88E6393X_SERDES_POC, &pcs0);
	pcs0 &= MV88E6393X_SERDES_POC_PCS_MODE_MASK;
	err = mv88e6390_serdes_read(chip, MV88E6393X_PORT9_LANE, MDIO_MMD_PHYXS,
				    MV88E6393X_SERDES_POC, &pcs9);
	pcs9 &= MV88E6393X_SERDES_POC_PCS_MODE_MASK;
	err = mv88e6390_serdes_read(chip, MV88E6393X_PORT10_LANE, MDIO_MMD_PHYXS,
				    MV88E6393X_SERDES_POC, &pcs10);
	pcs10 &= MV88E6393X_SERDES_POC_PCS_MODE_MASK;

	if (pcs0 == MV88E6393X_PCS_SELECT_1000BASEX ||
		pcs0 == MV88E6393X_PCS_SELECT_SGMII_PHY ||
		pcs0 == MV88E6393X_PCS_SELECT_SGMII_MAC) {
		config0 |= MV88E6393X_ERRATA_1000BASEX_SGMII_BIT;
		err = mv88e6390_serdes_write(chip, MV88E6393X_PORT0_LANE,
						MDIO_MMD_PHYXS,
						MV88E6393X_ERRATA_1000BASEX_SGMII,
						config0);
	} else {
		config0 &= ~MV88E6393X_ERRATA_1000BASEX_SGMII_BIT;
		err = mv88e6390_serdes_write(chip, MV88E6393X_PORT0_LANE,
						MDIO_MMD_PHYXS,
						MV88E6393X_ERRATA_1000BASEX_SGMII,
						config0);
	}

	if (pcs9 == MV88E6393X_PCS_SELECT_1000BASEX ||
		pcs9 == MV88E6393X_PCS_SELECT_SGMII_PHY ||
		pcs9 == MV88E6393X_PCS_SELECT_SGMII_MAC) {
		config9 |= MV88E6393X_ERRATA_1000BASEX_SGMII_BIT;
		err = mv88e6390_serdes_write(chip, MV88E6393X_PORT9_LANE,
						MDIO_MMD_PHYXS,
						MV88E6393X_ERRATA_1000BASEX_SGMII,
						config9);
	} else {
		config9 &= ~MV88E6393X_ERRATA_1000BASEX_SGMII_BIT;
		err = mv88e6390_serdes_write(chip, MV88E6393X_PORT9_LANE,
						MDIO_MMD_PHYXS,
						MV88E6393X_ERRATA_1000BASEX_SGMII,
						config9);
	}

	if (pcs10 == MV88E6393X_PCS_SELECT_1000BASEX ||
		pcs10 == MV88E6393X_PCS_SELECT_SGMII_PHY ||
		pcs10 == MV88E6393X_PCS_SELECT_SGMII_MAC) {
		config10 |= MV88E6393X_ERRATA_1000BASEX_SGMII_BIT;
		err = mv88e6390_serdes_write(chip, MV88E6393X_PORT10_LANE,
						MDIO_MMD_PHYXS,
						MV88E6393X_ERRATA_1000BASEX_SGMII,
						config10);
	} else {
		config10 &= ~MV88E6393X_ERRATA_1000BASEX_SGMII_BIT;
		err = mv88e6390_serdes_write(chip, MV88E6393X_PORT10_LANE,
						MDIO_MMD_PHYXS,
						MV88E6393X_ERRATA_1000BASEX_SGMII,
						config10);
	}
	return err;
}

static int mv88e6393x_serdes_port_config(struct mv88e6xxx_chip *chip, int lane,
					bool on)
{
	u8 cmode = chip->ports[lane].cmode;
	u16 config, pcs;

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
		pcs = MV88E6393X_PCS_SELECT_1000BASEX;
		break;
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
		pcs = MV88E6393X_PCS_SELECT_2500BASEX;
		break;
	case MV88E6XXX_PORT_STS_CMODE_10GBASER:
		pcs = MV88E6393X_PCS_SELECT_10GBASER;
		break;
	default:
		pcs = MV88E6393X_PCS_SELECT_1000BASEX;
		break;
	}

	if (on) {
		/* mv88e6393x family errata 3.6 :
		 * When changing c_mode on Port 0 from [x]MII mode to any
		 * SERDES mode SERDES will not be operational.
		 * Workaround: Set Port0 SERDES register 4.F002.5=0
		 */
		mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				MV88E6393X_SERDES_POC, &config);
		config &= ~(MV88E6393X_SERDES_POC_PCS_MODE_MASK |
				MV88E6393X_SERDES_POC_PDOWN);
		config |= pcs;
		mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				MV88E6393X_SERDES_POC, config);
		config |= MV88E6393X_SERDES_POC_RESET;
		mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				MV88E6393X_SERDES_POC, config);

		/* mv88e6393x family errata 3.7 :
		 * When changing cmode on SERDES port from any other mode to
		 * 1000BASE-X mode the link may not come up due to invalid
		 * 1000BASE-X advertisement.
		 * Workaround: Correct advertisement and reset PHY core.
		 */
		config = MV88E6390_SGMII_ANAR_1000BASEX_FD;
		mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				MV88E6390_SGMII_ANAR, config);

		/* soft reset the PCS/PMA */
		mv88e6390_serdes_read(chip, lane, MDIO_MMD_PHYXS,
				MV88E6390_SGMII_CONTROL, &config);
		config |= MV88E6390_SGMII_CONTROL_RESET;
		mv88e6390_serdes_write(chip, lane, MDIO_MMD_PHYXS,
				MV88E6390_SGMII_CONTROL, config);
	}

	return 0;
}

int mv88e6393x_serdes_power(struct mv88e6xxx_chip *chip, int port, int lane,
		    bool on)
{
	if (port != 0 && port != 9 && port != 10)
		return -EOPNOTSUPP;

	u8 cmode = chip->ports[port].cmode;

	mv88e6393x_serdes_port_config(chip, lane, on);

	switch (cmode) {
	case MV88E6XXX_PORT_STS_CMODE_1000BASEX:
	case MV88E6XXX_PORT_STS_CMODE_2500BASEX:
		return mv88e6390_serdes_power_sgmii(chip, lane, on);
	case MV88E6XXX_PORT_STS_CMODE_10GBASER:
		return mv88e6390_serdes_power_10g(chip, lane, on);
	}

	return 0;
}
