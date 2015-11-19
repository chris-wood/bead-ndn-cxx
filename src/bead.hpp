/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#ifndef NDN_BEAD_HPP
#define NDN_BEAD_HPP

#include "common.hpp"

#include "name.hpp"
#include "selectors.hpp"
#include "util/time.hpp"
#include "management/nfd-local-control-header.hpp"
#include "tag-host.hpp"
#include "link.hpp"

namespace ndn {

class Data;

/** @var const unspecified_duration_type DEFAULT_Bead_LIFETIME;
 *  @brief default value for BeadLifetime
 */
const time::milliseconds DEFAULT_Bead_LIFETIME = time::milliseconds(4000);

/** @brief represents an Bead packet
 */
class Bead : public TagHost, public enable_shared_from_this<Bead>
{
public:
  class Error : public tlv::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : tlv::Error(what)
    {
    }
  };

  /** @brief Create a new Bead with an empty name (`ndn:/`)
   *  @warning In certain contexts that use Bead::shared_from_this(), Bead must be created
   *           using `make_shared`. Otherwise, .shared_from_this() will throw an exception.
   */
  Bead();

  /** @brief Create a new Bead with the given name
   *  @param name The name for the Bead.
   *  @note This constructor allows implicit conversion from Name.
   *  @warning In certain contexts that use Bead::shared_from_this(), Bead must be created
   *           using `make_shared`. Otherwise, .shared_from_this() will throw an exception.
   */
  Bead(const Name& name);

  /** @brief Create a new Bead with the given name and Bead lifetime
   *  @param name             The name for the Bead.
   *  @param BeadLifetime The Bead lifetime in time::milliseconds, or -1 for none.
   *  @warning In certain contexts that use Bead::shared_from_this(), Bead must be created
   *           using `make_shared`. Otherwise, .shared_from_this() will throw an exception.
   */
  Bead(const Name& name, const time::milliseconds& BeadLifetime);

  /** @brief Create from wire encoding
   *  @warning In certain contexts that use Bead::shared_from_this(), Bead must be created
   *           using `make_shared`. Otherwise, .shared_from_this() will throw an exception.
   */
  explicit
  Bead(const Block& wire);

  /**
   * @brief Fast encoding or block size estimation
   */
  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  /**
   * @brief Encode to a wire format
   */
  const Block&
  wireEncode() const;

  /**
   * @brief Decode from the wire format
   */
  void
  wireDecode(const Block& wire);

  /**
   * @brief Check if already has wire
   */
  bool
  hasWire() const
  {
    return m_wire.hasWire();
  }

  /**
   * @brief Encode the name according to the NDN URI Scheme
   *
   * If there are Bead selectors, this method will append "?" and add the selectors as
   * a query string.  For example, "/test/name?ndn.ChildSelector=1"
   */
  std::string
  toUri() const;

public: // Link and forwarding hint

   /**
   * @brief Check whether the Bead contains a Link object
   * @return True if there is a link object, otherwise false
   */
  bool
  hasLink() const;

  /**
   * @brief Get the link object for this Bead
   * @return The link object if there is one contained in this Bead
   * @throws Bead::Error if there is no link object contained in the Bead
   */
  Link
  getLink() const;

  /**
   * @brief Set the link object for this Bead
   * @param link The link object that will be included in this Bead (in wire format)
   * @post !hasSelectedDelegation()
   */
  void
  setLink(const Block& link);

  /**
   *@brief Reset the wire format of the given Bead and the contained link
   */
  void
  unsetLink();

  /**
   * @brief Check whether the Bead includes a selected delegation
   * @return True if there is a selected delegation, otherwise false
   */
  bool
  hasSelectedDelegation() const;

  /**
   * @brief Get the name of the selected delegation
   * @return The name of the selected delegation
   * @throw Error SelectedDelegation is not set.
   */
  Name
  getSelectedDelegation() const;

  /**
   * @brief Set the selected delegation
   * @param delegationName The name of the selected delegation
   * @throw Error Link is not set.
   * @throw std::invalid_argument @p delegationName does not exist in Link.
   */
  void
  setSelectedDelegation(const Name& delegationName);

  /**
   * @brief Set the selected delegation
   * @param delegation The index of the selected delegation
   * @throw Error Link is not set.
   * @throw std::out_of_range @p delegationIndex is out of bound in Link.
   */
  void
  setSelectedDelegation(size_t delegationIndex);

   /**
   * @brief Unset the selected delegation
   */
  void
  unsetSelectedDelegation();

public: // matching
  /** @brief Check if Bead, including selectors, matches the given @p name
   *  @param name The name to be matched. If this is a Data name, it shall contain the
   *              implicit digest component
   */
  bool
  matchesName(const Name& name) const;

  /**
   * @brief Check if Bead can be satisfied by @p data.
   *
   * This method considers Name, MinSuffixComponents, MaxSuffixComponents,
   * PublisherPublicKeyLocator, and Exclude.
   * This method does not consider ChildSelector and MustBeFresh.
   *
   * @todo recognize implicit digest component
   */
  bool
  matchesData(const Data& data) const;

public: // Name and guiders
  const Name&
  getName() const
  {
    return m_name;
  }

  Bead&
  setName(const Name& name)
  {
    m_name = name;
    m_wire.reset();
    return *this;
  }

  std::string
  getToken() const;

  Bead&
  setToken(std::string token);

  const time::milliseconds&
  getBeadLifetime() const
  {
    return m_BeadLifetime;
  }

  Bead&
  setBeadLifetime(const time::milliseconds& BeadLifetime)
  {
    m_BeadLifetime = BeadLifetime;
    m_wire.reset();
    return *this;
  }

  /** @brief Check if Nonce set
   */
  bool
  hasNonce() const
  {
    return m_nonce.hasWire();
  }

  /** @brief Get Bead's nonce
   *
   *  If nonce was not set before this call, it will be automatically assigned to a random value
   */
  uint32_t
  getNonce() const;

  /** @brief Set Bead's nonce
   *
   *  If wire format already exists, this call simply replaces nonce in the
   *  existing wire format, without resetting and recreating it.
   */
  Bead&
  setNonce(uint32_t nonce);

  /** @brief Refresh nonce
   *
   *  It's guaranteed that new nonce value differs from the existing one.
   *
   *  If nonce is already set, it will be updated to a different random value.
   *  If nonce is not set, this method does nothing.
   */
  void
  refreshNonce();

public: // local control header
  nfd::LocalControlHeader&
  getLocalControlHeader()
  {
    return m_localControlHeader;
  }

  const nfd::LocalControlHeader&
  getLocalControlHeader() const
  {
    return m_localControlHeader;
  }

  uint64_t
  getIncomingFaceId() const
  {
    return getLocalControlHeader().getIncomingFaceId();
  }

  Bead&
  setIncomingFaceId(uint64_t incomingFaceId)
  {
    getLocalControlHeader().setIncomingFaceId(incomingFaceId);
    // ! do not reset Bead's wire !
    return *this;
  }

  uint64_t
  getNextHopFaceId() const
  {
    return getLocalControlHeader().getNextHopFaceId();
  }

  Bead&
  setNextHopFaceId(uint64_t nextHopFaceId)
  {
    getLocalControlHeader().setNextHopFaceId(nextHopFaceId);
    // ! do not reset Bead's wire !
    return *this;
  }

public: // Selectors
  /**
   * @return true if Bead has any selector present
   */
  bool
  hasSelectors() const
  {
    return !m_selectors.empty();
  }

  const Selectors&
  getSelectors() const
  {
    return m_selectors;
  }

  Bead&
  setSelectors(const Selectors& selectors)
  {
    m_selectors = selectors;
    m_wire.reset();
    return *this;
  }

  int
  getMinSuffixComponents() const
  {
    return m_selectors.getMinSuffixComponents();
  }

  Bead&
  setMinSuffixComponents(int minSuffixComponents)
  {
    m_selectors.setMinSuffixComponents(minSuffixComponents);
    m_wire.reset();
    return *this;
  }

  int
  getMaxSuffixComponents() const
  {
    return m_selectors.getMaxSuffixComponents();
  }

  Bead&
  setMaxSuffixComponents(int maxSuffixComponents)
  {
    m_selectors.setMaxSuffixComponents(maxSuffixComponents);
    m_wire.reset();
    return *this;
  }

  const KeyLocator&
  getPublisherPublicKeyLocator() const
  {
    return m_selectors.getPublisherPublicKeyLocator();
  }

  Bead&
  setPublisherPublicKeyLocator(const KeyLocator& keyLocator)
  {
    m_selectors.setPublisherPublicKeyLocator(keyLocator);
    m_wire.reset();
    return *this;
  }

  const Exclude&
  getExclude() const
  {
    return m_selectors.getExclude();
  }

  Bead&
  setExclude(const Exclude& exclude)
  {
    m_selectors.setExclude(exclude);
    m_wire.reset();
    return *this;
  }

  int
  getChildSelector() const
  {
    return m_selectors.getChildSelector();
  }

  Bead&
  setChildSelector(int childSelector)
  {
    m_selectors.setChildSelector(childSelector);
    m_wire.reset();
    return *this;
  }

  int
  getMustBeFresh() const
  {
    return m_selectors.getMustBeFresh();
  }

  Bead&
  setMustBeFresh(bool mustBeFresh)
  {
    m_selectors.setMustBeFresh(mustBeFresh);
    m_wire.reset();
    return *this;
  }

public: // EqualityComparable concept
  bool
  operator==(const Bead& other) const
  {
    return wireEncode() == other.wireEncode();
  }

  bool
  operator!=(const Bead& other) const
  {
    return !(*this == other);
  }

private:
  Name m_name;
  Selectors m_selectors;
  mutable Block m_nonce;
  mutable Block m_token;
  time::milliseconds m_BeadLifetime;

  mutable Block m_link;
  size_t m_selectedDelegationIndex;
  mutable Block m_wire;

  nfd::LocalControlHeader m_localControlHeader;
  friend class nfd::LocalControlHeader;
};

std::ostream&
operator<<(std::ostream& os, const Bead& Bead);

inline std::string
Bead::toUri() const
{
  std::ostringstream os;
  os << *this;
  return os.str();
}

} // namespace ndn

#endif // NDN_Bead_HPP
