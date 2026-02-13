# GOAD - Game Of Active Directory — Network Map

GOAD contains 3 domains across 2 forests, running on 5 virtual machines.

## Network Topology

### Domains and Domain Controllers

| Domain | DC | Hostname | IP | OS | Defender |
|--------|-----|----------|-----|-----|---------|
| sevenkingdoms.local | DC01 | kingslanding | 192.168.56.10 | Windows Server 2019 | Enabled |
| north.sevenkingdoms.local | DC02 | winterfell | 192.168.56.11 | Windows Server 2019 | Enabled |
| essos.local | DC03 | meereen | 192.168.56.12 | Windows Server 2016 | Enabled |

### Member Servers

| Server | Hostname | IP | OS | Services | Defender |
|--------|----------|-----|-----|----------|---------|
| SRV02 | castelblack | 192.168.56.22 | Windows Server 2019 | IIS, MSSQL, SMB | Disabled |
| SRV03 | braavos | 192.168.56.23 | Windows Server 2016 | MSSQL, SMB, ADCS (ESSOS-CA) | Enabled |

### Trust Relationships

- `north.sevenkingdoms.local` is a **child domain** of `sevenkingdoms.local`
- `essos.local` has a **forest trust** with `sevenkingdoms.local`
- MSSQL trusted links exist between `castelblack` and `braavos`

## Domain: SEVENKINGDOMS.LOCAL

### Domain Admins
- `robert.baratheon` (protected user)
- `cersei.lannister`

### Groups and Users

**BARATHEON** (RDP on KINGSLANDING)
- `robert.baratheon` — Domain Admin, protected user
- `joffrey.baratheon` — ACE: Write DACL on tyron.lannister
- `renly.baratheon` — WriteDACL on container, sensitive user
- `stannis.baratheon` — ACE: GenericAll on computer kingslanding

**LANNISTER**
- `tywin.lannister` — ACE: ForceChangePassword on jaime.lannister, password in sysvol (encrypted)
- `jaime.lannister` — ACE: GenericWrite on joffrey.baratheon
- `tyron.lannister` — ACE: Self-membership on Small Council
- `cersei.lannister` — Domain Admin

**SMALL COUNCIL** (RDP on KINGSLANDING, ACE: AddMember to Dragonstone)
- `petyer.baelish`
- `lord.varys` — ACE: GenericAll on Domain Admins and SDHolder
- `maester.pycelle`

**DRAGONSTONE** — ACE: WriteOwner on KINGSGUARD

**KINGSGUARD** — ACE: GenericAll on stannis.baratheon

## Domain: NORTH.SEVENKINGDOMS.LOCAL

### Domain Admins
- `eddard.stark` (bot: 5min LLMNR query)
- `catelyn.stark`
- `robb.stark` (bot: 3min LLMNR responder, lsass present user)

### Groups and Users

**STARKS** (RDP on WINTERFELL and CASTELBLACK)
- `arya.stark` — MSSQL execute-as-user, password on all shares
- `eddard.stark` — Domain Admin, LLMNR bot (NTLM relay target)
- `catelyn.stark` — Domain Admin
- `robb.stark` — LLMNR responder bot, lsass credential in memory
- `sansa.stark` — Keywalking password, unconstrained delegation
- `brandon.stark` — AS-REP roasting
- `rickon.stark` — Password spray (WinterYYYY)
- `jon.snow` — MSSQL admin, Kerberoasting, MSSQL trusted link

**NIGHT WATCH** (RDP on CASTELBLACK)
- `samwell.tarly` — Password in LDAP description, MSSQL execute-as-login, GPO abuse
- `jon.snow` — (see Starks)
- `jeor.mormont` — (see Mormont)

**MORMONT** (RDP on CASTELBLACK)
- `jeor.mormont` — Admin on castelblack, password in sysvol script

**AcrossTheSea** — Cross-forest group

## Domain: ESSOS.LOCAL

### Domain Admins
- `daenerys.targaryen`

### Groups and Users

**TARGARYEN** (RDP on MEEREEN)
- `missandei` — AS-REP roasting, GenericAll on khal.drogo
- `daenerys.targaryen` — Domain Admin
- `viserys.targaryen` — ACE: WriteProperty on jorah.mormont
- `jorah.mormont` — MSSQL execute-as-login, MSSQL trusted link, Read LAPS password

**DOTHRAKI** (RDP on BRAAVOS)
- `khal.drogo` — MSSQL admin, GenericAll on viserys (shadow credentials), GenericAll on ECS4

**DragonsFriends** — Cross-forest group

**Spys** — Cross-forest group, Read LAPS password, ACL GenericAll on jorah.mormont

## MSSQL Trust Chain

```
castelblack (jon.snow admin)
  ├── execute as login: samwell.tarly → sa
  ├── execute as user: arya.stark → dbo
  └── trusted link → braavos (jon.snow → sa)

braavos (khal.drogo admin)
  ├── execute as login: jorah.mormont → sa
  └── trusted link → castelblack (jorah.mormont → sa)
```

## Services

| Host | Service | Details |
|------|---------|---------|
| castelblack | IIS | ASP upload allowed, runs as NT Authority\Network |
| castelblack | MSSQL | Admin: jon.snow, execute-as and trusted links |
| castelblack | SMB | File share |
| braavos | MSSQL | Admin: khal.drogo, execute-as and trusted links |
| braavos | SMB | File share |
| braavos | ADCS | ESSOS-CA (Certificate Authority) |
